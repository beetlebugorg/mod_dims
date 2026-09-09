package moddims

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrBadEurl reports an eurl value that is not base64, is too short for its
// scheme, or fails its tag check.
var ErrBadEurl = errors.New("moddims: cannot read the eurl value")

// Cipher names the scheme an eurl value uses.
type Cipher int

const (
	// GCM is AES-128-GCM. /dims5/ reads it, and /dims4/ reads it under
	// DimsEncryptionAlgorithm AES/GCM/NoPadding.
	GCM Cipher = iota

	// ECB is AES-128-ECB with PKCS5 padding, the /dims4/ default. It has no
	// integrity check and no IV.
	ECB
)

// The AES key both schemes use, and what a GCM value has before and after the
// ciphertext.
const (
	keyBytes    = 16
	gcmIVBytes  = 12
	gcmTagBytes = 16
	blockBytes  = 16
)

// kdfSalt is the salt the key derivation uses. Changing it invalidates every
// eurl.
var kdfSalt = []byte("go-dims")

// DeriveKey returns the AES key an eurl value uses.
//
// A secret with a sha1: prefix uses the older path: SHA-1 of the rest, hex
// encoded, the first 16 characters uppercased. Anything else uses
// HKDF-SHA256, with a hkdf: prefix stripped first.
//
// /dims4/ reads the older path whatever the secret looks like, so a /dims4/
// caller writes sha1: in front of the client secret.
func DeriveKey(secret string) ([]byte, error) {
	if secret == "" {
		return nil, fmt.Errorf("moddims: %w", ErrNoKey)
	}

	if rest, ok := strings.CutPrefix(secret, "sha1:"); ok {
		sum := sha1.Sum([]byte(rest))
		return []byte(strings.ToUpper(hex.EncodeToString(sum[:]))[:keyBytes]), nil
	}

	secret, _ = strings.CutPrefix(secret, "hkdf:")

	key, err := hkdf.Key(sha256.New, []byte(secret), kdfSalt, "", keyBytes)
	if err != nil {
		return nil, fmt.Errorf("moddims: %w", err)
	}

	return key, nil
}

// Encrypt returns the eurl value for one image URL.
//
// A GCM value is the 12 byte IV, the ciphertext, and the 16 byte tag, base64
// encoded. The IV comes from crypto/rand, so two calls on one URL under one
// key produce two values. An ECB value is the ciphertext alone.
func Encrypt(imageURL string, key []byte, c Cipher) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("moddims: %w", err)
	}

	if c == ECB {
		return base64.StdEncoding.EncodeToString(ecbEncrypt(block, []byte(imageURL))), nil
	}

	iv := make([]byte, gcmIVBytes)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("moddims: %w", err)
	}

	mode, err := cipher.NewGCMWithNonceSize(block, gcmIVBytes)
	if err != nil {
		return "", fmt.Errorf("moddims: %w", err)
	}

	// Seal appends the ciphertext and the tag to the IV, which is the framing
	// the module reads.
	return base64.StdEncoding.EncodeToString(
		mode.Seal(iv, iv, []byte(imageURL), nil)), nil
}

// Decrypt returns the image URL one eurl value holds, so a caller reads back
// what it wrote.
//
// A returned error wraps ErrBadEurl.
func Decrypt(eurl string, key []byte, c Cipher) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(eurl)
	if err != nil {
		return "", fmt.Errorf("moddims: %w", ErrBadEurl)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("moddims: %w", err)
	}

	if c == ECB {
		plain, err := ecbDecrypt(block, bytes)
		if err != nil {
			return "", err
		}
		return string(plain), nil
	}

	if len(bytes) <= gcmIVBytes+gcmTagBytes {
		return "", fmt.Errorf("moddims: %w", ErrBadEurl)
	}

	mode, err := cipher.NewGCMWithNonceSize(block, gcmIVBytes)
	if err != nil {
		return "", fmt.Errorf("moddims: %w", err)
	}

	// The tag check happens here. A value someone edited fails.
	plain, err := mode.Open(nil, bytes[:gcmIVBytes], bytes[gcmIVBytes:], nil)
	if err != nil {
		return "", fmt.Errorf("moddims: %w", ErrBadEurl)
	}

	return string(plain), nil
}

// The standard library has no ECB mode, so these two do the blocks. PKCS5
// padding adds up to one whole block.
func ecbEncrypt(block cipher.Block, plain []byte) []byte {
	padding := blockBytes - len(plain)%blockBytes
	padded := make([]byte, len(plain)+padding)
	copy(padded, plain)

	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(padding)
	}

	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += blockBytes {
		block.Encrypt(out[i:i+blockBytes], padded[i:i+blockBytes])
	}

	return out
}

func ecbDecrypt(block cipher.Block, encrypted []byte) ([]byte, error) {
	if len(encrypted) < blockBytes || len(encrypted)%blockBytes != 0 {
		return nil, fmt.Errorf("moddims: %w", ErrBadEurl)
	}

	out := make([]byte, len(encrypted))
	for i := 0; i < len(encrypted); i += blockBytes {
		block.Decrypt(out[i:i+blockBytes], encrypted[i:i+blockBytes])
	}

	padding := int(out[len(out)-1])
	if padding == 0 || padding > blockBytes || padding > len(out) {
		return nil, fmt.Errorf("moddims: %w", ErrBadEurl)
	}

	for _, b := range out[len(out)-padding:] {
		if int(b) != padding {
			return nil, fmt.Errorf("moddims: %w", ErrBadEurl)
		}
	}

	return out[:len(out)-padding], nil
}

// SignEncrypted returns rawURL with a valid /dims5/ signature and the image
// URL encrypted into eurl. The signature covers the plain image URL, so the
// server verifies the request after it decrypts.
//
// The value is percent encoded, because the module decodes that parameter.
func (s Dims5) SignEncrypted(rawURL string) (string, error) {
	signed, err := s.Sign(rawURL)
	if err != nil {
		return "", err
	}

	_, imageURL, _, _, err := dims5Fields(rawURL, s.Prefix)
	if err != nil {
		return "", err
	}

	key, err := DeriveKey(s.Key)
	if err != nil {
		return "", err
	}

	eurl, err := Encrypt(imageURL, key, GCM)
	if err != nil {
		return "", err
	}

	return swapURLForEurl(signed, url.QueryEscape(eurl)), nil
}

// SignEncrypted returns rawURL with a valid /dims4/ signature and the image
// URL encrypted into eurl. c names the scheme the server is configured for.
//
// The value travels undecoded, because the module reads that parameter as it
// appears in the query.
func (s Dims4) SignEncrypted(rawURL string, c Cipher) (string, error) {
	signed, err := s.Sign(rawURL)
	if err != nil {
		return "", err
	}

	f, err := dims4Fields(rawURL, s.Prefix)
	if err != nil {
		return "", err
	}

	// This endpoint reads one derivation whatever the secret looks like.
	key, err := DeriveKey("sha1:" + s.Secret)
	if err != nil {
		return "", err
	}

	eurl, err := Encrypt(f.imageURL, key, c)
	if err != nil {
		return "", err
	}

	return swapURLForEurl(signed, eurl), nil
}

// swapURLForEurl copies a signed URL with every url parameter replaced by one
// eurl. The eurl goes where the last url was, so the output holds the
// parameters in the order the input gave. Neither name is in the canonical
// query, so the signature still matches.
func swapURLForEurl(signedURL, eurl string) string {
	parts := splitURL(signedURL)

	tokens := strings.Split(parts.query, "&")
	last := -1
	for i, token := range tokens {
		if strings.HasPrefix(token, "url=") {
			last = i
		}
	}

	kept := make([]string, 0, len(tokens))
	for i, token := range tokens {
		switch {
		case token == "":
		case !strings.HasPrefix(token, "url="):
			kept = append(kept, token)
		case i == last:
			kept = append(kept, "eurl="+eurl)
		}
	}

	return signedURL[:parts.pathEnd] + "?" + strings.Join(kept, "&")
}
