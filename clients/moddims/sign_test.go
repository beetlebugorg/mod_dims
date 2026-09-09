package moddims

import (
	"errors"
	"net/url"
	"strings"
	"testing"
)

const (
	testKey    = "0123456789abcdef0123456789abcdef"
	testSecret = "t3stk3y"
	testImage  = "http%3A%2F%2Forigin%3A8080%2Fgrid.png"
)

// A record in the fixture file always has a key, so the empty one is checked
// here.
func TestSignWithoutAKey(t *testing.T) {
	if _, err := (Dims5{}).Sign("/dims5/resize/1x1/?url=" + testImage); !errors.Is(err, ErrNoKey) {
		t.Errorf("/dims5/ with no key: want ErrNoKey, got %v", err)
	}

	if _, err := (Dims4{}).Sign("/dims4/T/xxxxxx/2147483647/resize/1x1/?url=" + testImage); !errors.Is(err, ErrNoKey) {
		t.Errorf("/dims4/ with no secret: want ErrNoKey, got %v", err)
	}
}

// canonicalQuery relies on url.QueryEscape for the third line of the message.
// These are the properties it relies on, so a change to the standard library
// fails here rather than in a signature nobody can explain.
func TestQueryEscapeMatchesTheModule(t *testing.T) {
	cases := map[string]string{
		"abcXYZ019": "abcXYZ019",
		"-_.~":      "-_.~",
		" ":         "+",
		"a b":       "a+b",
		"+":         "%2B",
		"/":         "%2F",
		":":         "%3A",
		"&":         "%26",
		"=":         "%3D",
		"%":         "%25",
		"*":         "%2A",
	}

	for in, want := range cases {
		if got := url.QueryEscape(in); got != want {
			t.Errorf("QueryEscape(%q): want %q, got %q", in, want, got)
		}
	}
}

// url.Values.Encode orders by the bytes of the name. An order by rune puts
// U+10000 before U+FF21, and the module puts it after.
func TestCanonicalQueryOrdersByByte(t *testing.T) {
	got := canonicalQuery("%F0%90%80%80=1&%EF%BC%A1=2")
	want := "%EF%BC%A1=2&%F0%90%80%80=1"

	if got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

// A name with several values keeps the order the query gives.
func TestCanonicalQueryKeepsValueOrder(t *testing.T) {
	if got := canonicalQuery("tag=b&tag=a"); got != "tag=b&tag=a" {
		t.Errorf("want %q, got %q", "tag=b&tag=a", got)
	}
}

// decodeComponent copies a malformed escape, because the module does. Every
// fixture record with a malformed escape has it in the path, where the signer
// reports ErrBadURL instead.
func TestDecodeComponentCopiesAMalformedEscape(t *testing.T) {
	cases := map[string]string{
		"%zz":   "%zz",
		"%2":    "%2",
		"a+b":   "a b",
		"%2F":   "/",
		"50%25": "50%",
	}

	for in, want := range cases {
		if got := decodeComponent(in); got != want {
			t.Errorf("decodeComponent(%q): want %q, got %q", in, want, got)
		}
	}
}

// stripSig drops a sig parameter with no equals sign too, which no fixture
// record has.
func TestStripSig(t *testing.T) {
	cases := map[string]string{
		"url=a&sig=b":    "url=a",
		"sig=b&url=a":    "url=a",
		"url=a&sig":      "url=a",
		"url=a&signed=b": "url=a&signed=b",
		"sig=b":          "",
	}

	for in, want := range cases {
		if got := stripSig(in); got != want {
			t.Errorf("stripSig(%q): want %q, got %q", in, want, got)
		}
	}
}

// The last url in the query is the image URL, and a name is compared as it
// appears.
func TestRawValueTakesTheLast(t *testing.T) {
	value, found := rawValue("url=first&tag=x&url=second", "url")
	if !found || value != "second" {
		t.Errorf("want \"second\", got %q (found %v)", value, found)
	}

	if _, found := rawValue("ur%6c=x", "url"); found {
		t.Error("a percent escape in a name must not match")
	}
}

// A URL with no query has no url parameter.
func TestSignWithoutAQuery(t *testing.T) {
	_, err := Dims5{Key: testKey}.Sign("/dims5/resize/100x100/")
	if !errors.Is(err, ErrBadURL) {
		t.Errorf("want ErrBadURL, got %v", err)
	}
}

// An absolute URL keeps its scheme and authority.
func TestSignKeepsTheAuthority(t *testing.T) {
	in := "https://images.example.com/dims5/resize/100x100/?url=" + testImage
	want := in + "&sig=e9d70afb0b29520bae7fa47fb3de2d4c62c85f40d89636f6b190ac8055838bff"

	got, err := Dims5{Key: testKey}.Sign(in)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got != want {
		t.Errorf("want %s, got %s", want, got)
	}
}

// A placeholder longer than the digest has no digest to fill it.
func TestDims4PlaceholderTooLong(t *testing.T) {
	in := "/dims4/TEST/" + "x" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
		"/2147483647/resize/100x100/?url=" + testImage

	if _, err := (Dims4{Secret: testSecret}).Sign(in); !errors.Is(err, ErrBadURL) {
		t.Errorf("want ErrBadURL, got %v", err)
	}
}

// The two derivations. The HKDF value is checked against a ciphertext an
// independent implementation produced, in the eurl-dims5-gcm fixture record.
func TestDeriveKey(t *testing.T) {
	hkdfKey, err := DeriveKey(testKey)
	if err != nil {
		t.Fatalf("hkdf: %v", err)
	}

	prefixed, err := DeriveKey("hkdf:" + testKey)
	if err != nil {
		t.Fatalf("hkdf prefix: %v", err)
	}
	if string(hkdfKey) != string(prefixed) {
		t.Error("the hkdf prefix names the default")
	}

	// SHA-1 of t3stk3y is f4fd45f7f87ca8d7..., and the key is the first
	// sixteen characters of that, uppercased.
	sha1Key, err := DeriveKey("sha1:" + testSecret)
	if err != nil {
		t.Fatalf("sha1: %v", err)
	}
	if string(sha1Key) != "F4FD45F7F87CA8D7" {
		t.Errorf("sha1 key: got %q", sha1Key)
	}

	if _, err := DeriveKey(""); !errors.Is(err, ErrNoKey) {
		t.Errorf("an empty secret: want ErrNoKey, got %v", err)
	}
}

// A fresh IV every call on GCM, and one value every call on ECB.
func TestEncryptIsFreshOnlyForGcm(t *testing.T) {
	key, err := DeriveKey(testKey)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	first, err := Encrypt("http://origin:8080/grid.png", key, GCM)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	second, err := Encrypt("http://origin:8080/grid.png", key, GCM)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if first == second {
		t.Error("two GCM calls must produce two values")
	}

	third, err := Encrypt("http://origin:8080/grid.png", key, ECB)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	fourth, err := Encrypt("http://origin:8080/grid.png", key, ECB)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if third != fourth {
		t.Error("two ECB calls must produce one value")
	}
}

// A value the decoder cannot read.
func TestDecryptRefusesABadValue(t *testing.T) {
	key, err := DeriveKey(testKey)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	for _, value := range []string{"!!!!", "AAAA", ""} {
		if _, err := Decrypt(value, key, GCM); !errors.Is(err, ErrBadEurl) {
			t.Errorf("GCM %q: want ErrBadEurl, got %v", value, err)
		}
	}

	for _, value := range []string{"!!!!", "AAAA"} {
		if _, err := Decrypt(value, key, ECB); !errors.Is(err, ErrBadEurl) {
			t.Errorf("ECB %q: want ErrBadEurl, got %v", value, err)
		}
	}
}

// The signed URL holds eurl in place of url, and the signature is the one the
// plain URL produces.
func TestSignEncrypted(t *testing.T) {
	input := "/dims5/resize/100x100/?url=" + testImage

	plain, err := Dims5{Key: testKey}.Sign(input)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	encrypted, err := Dims5{Key: testKey}.SignEncrypted(input)
	if err != nil {
		t.Fatalf("sign encrypted: %v", err)
	}

	digest := plain[strings.Index(plain, "&sig="):]
	if !strings.HasSuffix(encrypted, digest) {
		t.Errorf("the signature must cover the plain image URL:\n %s\n %s",
			plain, encrypted)
	}

	if !strings.Contains(encrypted, "eurl=") {
		t.Error("the output must hold eurl")
	}
	if strings.Contains(encrypted, "?url=") || strings.Contains(encrypted, "&url=") {
		t.Error("the output must hold no url")
	}
}
