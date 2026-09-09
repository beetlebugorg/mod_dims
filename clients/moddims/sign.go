// Package moddims signs mod_dims URLs.
//
// The rules are the ones in sign/src/sign.c, which the module compiles.
// test/fixtures/signing.tsv holds a case for each of them, and
// fixture_test.go reads that file.
package moddims

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Dims5Prefix and Dims4Prefix are the prefixes each endpoint conventionally
// serves at. An empty Prefix means the matching one.
const (
	Dims5Prefix = "/dims5/"
	Dims4Prefix = "/dims4/"
)

// dims4SignatureLength is how many characters of the digest the module
// compares. dims4DigestLength is the whole hex MD5, which is the longest
// placeholder a caller may write.
const (
	dims4SignatureLength = 6
	dims4DigestLength    = 32
)

var (
	// ErrNoKey reports an empty Key or Secret.
	ErrNoKey = errors.New("moddims: no key")

	// ErrBadURL reports a URL the signer cannot read: the path does not start
	// with the prefix, a percent escape is malformed, the query has no url, or
	// a /dims4/ path is missing a segment.
	ErrBadURL = errors.New("moddims: cannot read the URL")

	// ErrBadField reports a control character in the commands or the image
	// URL.
	ErrBadField = errors.New("moddims: control character in a signed field")
)

// unsignedParams take no part in the canonical query.
var unsignedParams = map[string]bool{
	"sig": true, "url": true, "eurl": true, "_keys": true, "download": true,
}

// Dims5 signs URLs for the /dims5/ endpoint. The zero value is not usable,
// because Key is required. A Dims5 holds no other state and is safe to share
// between goroutines.
type Dims5 struct {
	// Key is the DimsSigningKey.
	Key string

	// Prefix is what comes before the commands in the path. "" means
	// Dims5Prefix. A caller behind a rewrite sets the public prefix.
	Prefix string
}

// Sign returns rawURL with a valid /dims5/ signature. The signature covers
// everything between Prefix and the query. sig goes on the end of the query,
// and an input that already holds one gets a new one in its place.
//
// A returned error wraps ErrNoKey, ErrBadURL, or ErrBadField.
func (s Dims5) Sign(rawURL string) (string, error) {
	if s.Key == "" {
		return "", fmt.Errorf("moddims: /dims5/: %w", ErrNoKey)
	}

	commands, imageURL, canonical, parts, err := dims5Fields(rawURL, s.Prefix)
	if err != nil {
		return "", err
	}

	if !fieldOK(commands) || !fieldOK(imageURL) {
		return "", fmt.Errorf("moddims: /dims5/: %w", ErrBadField)
	}

	message := commands + "\n" + imageURL + "\n" + canonical

	mac := hmac.New(sha256.New, []byte(s.Key))
	mac.Write([]byte(message))
	digest := hex.EncodeToString(mac.Sum(nil))

	query := stripSig(parts.query)
	if query != "" {
		query += "&"
	}

	return rawURL[:parts.pathEnd] + "?" + query + "sig=" + digest, nil
}

// Dims4 signs URLs for the /dims4/ endpoint. Secret is required.
type Dims4 struct {
	// Secret is the client secret.
	Secret string

	// Prefix is what comes before the client id. "" means Dims4Prefix.
	Prefix string
}

// Sign returns rawURL with a valid /dims4/ signature. Four segments follow
// Prefix: the client id, the signature, the expiry, and the commands. The
// caller writes a placeholder in the signature segment, and its length sets
// the length of the signature, from 6 characters to 32.
//
// The image URL signs with every plus written as a space, which is what the
// module does on this endpoint. Dims5 keeps the plus.
//
// A returned error wraps ErrNoKey or ErrBadURL.
func (s Dims4) Sign(rawURL string) (string, error) {
	if s.Secret == "" {
		return "", fmt.Errorf("moddims: /dims4/: %w", ErrNoKey)
	}

	f, err := dims4Fields(rawURL, s.Prefix)
	if err != nil {
		return "", err
	}

	digest := fmt.Sprintf("%x", md5.Sum([]byte(dims4Message(s.Secret, f))))

	// The path is rebuilt from its four segments, so a placeholder equal to
	// the client id or to the expiry still works.
	var out strings.Builder
	out.WriteString(rawURL[:f.clientStart])
	out.WriteString(f.client)
	out.WriteString("/")
	out.WriteString(digest[:len(f.signature)])
	out.WriteString("/")
	out.WriteString(f.expires)
	out.WriteString("/")
	out.WriteString(f.rawCommands)
	if f.hasQuery {
		out.WriteString("?")
		out.WriteString(f.query)
	}

	return out.String(), nil
}

// -- Reading a URL --

// urlParts is the path and the query of one URL, with the offset where the
// path ends so a caller can rebuild the URL around it.
type urlParts struct {
	path     string
	pathEnd  int
	query    string
	hasQuery bool
}

// pathStart is the index where the path begins. An absolute URL has an
// authority before it.
func pathStart(rawURL string) int {
	i := 0
	for i < len(rawURL) && isSchemeByte(rawURL[i]) {
		i++
	}

	if i == 0 || !strings.HasPrefix(rawURL[i:], "://") {
		return 0
	}

	i += 3
	for i < len(rawURL) && rawURL[i] != '/' && rawURL[i] != '?' {
		i++
	}

	return i
}

func isSchemeByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'
}

func splitURL(rawURL string) urlParts {
	start := pathStart(rawURL)
	rest := rawURL[start:]

	if i := strings.IndexByte(rest, '?'); i >= 0 {
		return urlParts{
			path:     rest[:i],
			pathEnd:  start + i,
			query:    rest[i+1:],
			hasQuery: true,
		}
	}

	return urlParts{path: rest, pathEnd: len(rawURL)}
}

// afterPrefix is the path with prefix removed.
func afterPrefix(path, prefix string) (string, error) {
	if !strings.HasPrefix(path, prefix) {
		return "", fmt.Errorf("moddims: %q does not start with %q: %w",
			path, prefix, ErrBadURL)
	}

	return path[len(prefix):], nil
}

// -- Percent coding --

// decodeStrict decodes a path or an image URL. A plus stays a plus, because
// the module decodes both with ap_unescape_url, which does not read a plus as
// a space.
//
// A percent escape that is not two hex digits is an error, and so is %00: the
// C library cannot hold the byte it decodes to, so it refuses one too.
func decodeStrict(text string) (string, error) {
	out, err := url.PathUnescape(text)
	if err != nil {
		return "", fmt.Errorf("moddims: %w", ErrBadURL)
	}

	if strings.IndexByte(out, 0) >= 0 {
		return "", fmt.Errorf("moddims: %%00 in a signed field: %w", ErrBadURL)
	}

	return out, nil
}

// decodeComponent decodes one query component the way the module does. A plus
// is a space, and a percent escape that is not two hex digits passes through
// as it is. url.QueryUnescape reports an error on that escape instead, so this
// does the decoding itself.
func decodeComponent(text string) string {
	var out strings.Builder

	for i := 0; i < len(text); i++ {
		switch {
		case text[i] == '+':
			out.WriteByte(' ')
		case text[i] == '%' && i+2 < len(text) &&
			isHex(text[i+1]) && isHex(text[i+2]):
			out.WriteByte(hexValue(text[i+1])<<4 | hexValue(text[i+2]))
			i += 2
		default:
			out.WriteByte(text[i])
		}
	}

	return out.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexValue(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// -- The canonical query --

// canonicalQuery builds the third line of a /dims5/ message.
//
// url.Values.Encode produces the right bytes: it sorts by the key, it keeps
// the order of the values under one key, and url.QueryEscape keeps
// A-Za-z0-9-_.~ and writes a space as a plus. The sort compares Go strings
// byte by byte, and it must stay that way: the module orders by UTF-8 byte,
// and an order by rune disagrees above U+FFFF.
//
// url.ParseQuery does not read the input. It decodes a plus in url as a space
// and reports an error on a semicolon, and the module does neither.
func canonicalQuery(query string) string {
	values := url.Values{}

	for _, token := range strings.Split(query, "&") {
		if token == "" {
			continue
		}

		name, value := token, ""
		if i := strings.IndexByte(token, '='); i >= 0 {
			// A parameter with no equals sign has an empty value.
			name, value = token[:i], token[i+1:]
		}

		name = decodeComponent(name)
		if unsignedParams[name] {
			continue
		}

		values.Add(name, decodeComponent(value))
	}

	return values.Encode()
}

// rawValue is the last value of one query parameter, undecoded.
//
// The name is compared as it appears in the query. The module reads the query
// the same way, so a percent escape in a name does not match here either.
func rawValue(query, name string) (string, bool) {
	value, found := "", false

	for _, token := range strings.Split(query, "&") {
		if rest, ok := strings.CutPrefix(token, name+"="); ok {
			value, found = rest, true
		}
	}

	return value, found
}

// stripSig is the query with every sig parameter left out.
func stripSig(query string) string {
	kept := make([]string, 0, 8)

	for _, token := range strings.Split(query, "&") {
		if token == "" {
			continue
		}

		name := token
		if i := strings.IndexByte(token, '='); i >= 0 {
			name = token[:i]
		}

		if name != "sig" {
			kept = append(kept, token)
		}
	}

	return strings.Join(kept, "&")
}

// fieldOK reports whether a field is safe to put in a /dims5/ message. The
// message puts one field per line, so a field holding a newline could stand in
// for two.
func fieldOK(field string) bool {
	for i := 0; i < len(field); i++ {
		if field[i] < 0x20 || field[i] == 0x7F {
			return false
		}
	}

	return true
}

// -- /dims5/ --

func dims5Fields(rawURL, prefix string) (commands, imageURL, canonical string, parts urlParts, err error) {
	if prefix == "" {
		prefix = Dims5Prefix
	}

	parts = splitURL(rawURL)

	rest, err := afterPrefix(parts.path, prefix)
	if err != nil {
		return "", "", "", parts, err
	}

	commands, err = decodeStrict(rest)
	if err != nil {
		return "", "", "", parts, err
	}

	raw, found := rawValue(parts.query, "url")
	if !found {
		return "", "", "", parts, fmt.Errorf("moddims: the query has no url: %w", ErrBadURL)
	}

	imageURL, err = decodeStrict(raw)
	if err != nil {
		return "", "", "", parts, err
	}

	return commands, imageURL, canonicalQuery(parts.query), parts, nil
}

// dims5Message is the message Dims5.Sign hashes. fixture_test.go asserts it,
// so a difference names the line that went wrong.
func dims5Message(rawURL, prefix string) (string, error) {
	commands, imageURL, canonical, _, err := dims5Fields(rawURL, prefix)
	if err != nil {
		return "", err
	}

	return commands + "\n" + imageURL + "\n" + canonical, nil
}

// -- /dims4/ --

// dims4Path is everything a /dims4/ signature covers, read out of one URL.
type dims4Path struct {
	clientStart int
	client      string
	signature   string
	expires     string
	rawCommands string
	commands    string
	imageURL    string
	keys        []string
	values      []string
	query       string
	hasQuery    bool
}

func dims4Fields(rawURL, prefix string) (dims4Path, error) {
	var f dims4Path

	if prefix == "" {
		prefix = Dims4Prefix
	}

	parts := splitURL(rawURL)
	f.query, f.hasQuery = parts.query, parts.hasQuery

	rest, err := afterPrefix(parts.path, prefix)
	if err != nil {
		return f, err
	}

	f.clientStart = parts.pathEnd - len(rest)

	segments := strings.SplitN(rest, "/", 4)
	if len(segments) < 4 {
		return f, fmt.Errorf("moddims: %q has fewer than four segments after %q: %w",
			parts.path, prefix, ErrBadURL)
	}

	f.client, f.signature, f.expires, f.rawCommands =
		segments[0], segments[1], segments[2], segments[3]

	// The module reads the expiry with atol, so any other text expires it.
	if f.expires == "" || strings.TrimLeft(f.expires, "0123456789") != "" {
		return f, fmt.Errorf("moddims: expiry %q is not decimal digits: %w",
			f.expires, ErrBadURL)
	}

	// The placeholder sets the length of the signature.
	if len(f.signature) < dims4SignatureLength || len(f.signature) > dims4DigestLength {
		return f, fmt.Errorf("moddims: the signature placeholder is %d characters: %w",
			len(f.signature), ErrBadURL)
	}

	commands, err := decodeStrict(f.rawCommands)
	if err != nil {
		return f, err
	}

	// A space travels as %20 and signs as a plus.
	f.commands = strings.ReplaceAll(commands, " ", "+")

	raw, found := rawValue(parts.query, "url")
	if !found {
		return f, fmt.Errorf("moddims: the query has no url: %w", ErrBadURL)
	}

	imageURL, err := decodeStrict(raw)
	if err != nil {
		return f, err
	}

	// The module writes every plus in a /dims4/ image URL as a space after it
	// decodes the value.
	f.imageURL = strings.ReplaceAll(imageURL, "+", " ")

	// The values _keys names, in _keys order, as they appear in the query. A
	// name the query leaves out contributes nothing.
	if keys, ok := rawValue(parts.query, "_keys"); ok {
		for _, name := range strings.Split(keys, ",") {
			if name == "" {
				continue
			}

			value, _ := rawValue(parts.query, name)
			f.keys = append(f.keys, name)
			f.values = append(f.values, value)
		}
	}

	return f, nil
}

// dims4Message is the message Dims4.Sign hashes. It holds the client secret,
// so it stays unexported.
func dims4Message(secret string, f dims4Path) string {
	var out strings.Builder

	out.WriteString(f.expires)
	out.WriteString(secret)
	out.WriteString(f.commands)
	out.WriteString(f.imageURL)
	for _, value := range f.values {
		out.WriteString(value)
	}

	return out.String()
}
