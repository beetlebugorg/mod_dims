package moddims

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"
)

// The file the C library, this package, and the Java client all read.
const fixtureFile = "../../test/fixtures/signing.tsv"

type fixture struct {
	name     string
	endpoint string
	prefix   string
	key      string
	cipher   string
	input    string

	signed     string
	message    string
	plain      string
	errName    string
	hasSigned  bool
	hasMessage bool
	hasPlain   bool
	hasError   bool
}

// unescape reads the three sequences the file uses.
func unescape(value string) string {
	var out strings.Builder

	for i := 0; i < len(value); i++ {
		if value[i] != '\\' || i+1 == len(value) {
			out.WriteByte(value[i])
			continue
		}

		i++
		switch value[i] {
		case 'n':
			out.WriteByte('\n')
		case 't':
			out.WriteByte('\t')
		default:
			out.WriteByte(value[i])
		}
	}

	return out.String()
}

func (f *fixture) set(t *testing.T, name, value string) {
	t.Helper()

	switch name {
	case "case":
		f.name = value
	case "endpoint":
		f.endpoint = value
	case "prefix":
		f.prefix = value
	case "key":
		f.key = value
	case "cipher":
		f.cipher = value
	case "input":
		f.input = value
	case "signed":
		f.signed, f.hasSigned = value, true
	case "message":
		f.message, f.hasMessage = value, true
	case "plain":
		f.plain, f.hasPlain = value, true
	case "error":
		f.errName, f.hasError = value, true
	case "query":
		// The canonical query is checked by the C suite.
	default:
		t.Fatalf("unknown field %q", name)
	}
}

// readFixtures reads every record. A blank line ends a record, and a line
// starting with # is a comment. A run that cannot open the file fails.
func readFixtures(t *testing.T) []fixture {
	t.Helper()

	file, err := os.Open(fixtureFile)
	if err != nil {
		t.Fatalf("cannot open %s: %v", fixtureFile, err)
	}
	defer file.Close()

	var records []fixture
	var current fixture
	open := false

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			if open {
				records = append(records, current)
				current, open = fixture{}, false
			}
			continue
		}

		if strings.HasPrefix(line, "#") {
			continue
		}

		name, value, found := strings.Cut(line, "\t")
		if !found {
			t.Fatalf("a line has no tab: %s", line)
		}

		current.set(t, name, unescape(value))
		open = true
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("cannot read %s: %v", fixtureFile, err)
	}

	if open {
		records = append(records, current)
	}

	return records
}

func (f fixture) sign() (string, error) {
	if f.endpoint == "dims5" {
		return Dims5{Key: f.key, Prefix: f.prefix}.Sign(f.input)
	}

	return Dims4{Secret: f.key, Prefix: f.prefix}.Sign(f.input)
}

func (f fixture) buildMessage() (string, error) {
	if f.endpoint == "dims5" {
		return dims5Message(f.input, f.prefix)
	}

	prefix := f.prefix
	if prefix == "" {
		prefix = Dims4Prefix
	}

	path, err := dims4Fields(f.input, prefix)
	if err != nil {
		return "", err
	}

	return dims4Message(f.key, path), nil
}

var sentinels = map[string]error{
	"bad-url":      ErrBadURL,
	"bad-field":    ErrBadField,
	"bad-argument": ErrNoKey,
	"bad-eurl":     ErrBadEurl,
}

func (f fixture) cipherKind() Cipher {
	if f.cipher == "ecb" {
		return ECB
	}

	return GCM
}

// An eurl record goes the other way: decrypt input under the key and compare
// it with plain. The suite then round trips its own encrypt through its own
// decrypt, because a fresh nonce means the file cannot pin a ciphertext.
func checkEurl(t *testing.T, f fixture) {
	t.Helper()

	key, err := DeriveKey(f.key)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	plain, err := Decrypt(f.input, key, f.cipherKind())

	if f.hasError {
		want, ok := sentinels[f.errName]
		if !ok {
			t.Fatalf("unknown error %q", f.errName)
		}
		if !errors.Is(err, want) {
			t.Fatalf("want %v, got %v", want, err)
		}
		return
	}

	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plain != f.plain {
		t.Errorf("plain:\n want %q\n  got %q", f.plain, plain)
	}

	again, err := Encrypt(f.plain, key, f.cipherKind())
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	back, err := Decrypt(again, key, f.cipherKind())
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if back != f.plain {
		t.Errorf("round trip:\n want %q\n  got %q", f.plain, back)
	}
}

// Every record in the shared fixture file, one subtest per case.
func TestFixtures(t *testing.T) {
	records := readFixtures(t)
	if len(records) < 30 {
		t.Fatalf("the fixture file holds %d records", len(records))
	}

	for _, f := range records {
		t.Run(f.name, func(t *testing.T) {
			if f.endpoint == "eurl" {
				checkEurl(t, f)
				return
			}

			if f.endpoint != "dims4" && f.endpoint != "dims5" {
				t.Fatalf("unknown endpoint %q", f.endpoint)
			}

			signed, err := f.sign()

			if f.hasError {
				want, ok := sentinels[f.errName]
				if !ok {
					t.Fatalf("unknown error %q", f.errName)
				}
				if !errors.Is(err, want) {
					t.Fatalf("want %v, got %v", want, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if !f.hasSigned {
				t.Fatal("a record needs signed or error")
			}
			if signed != f.signed {
				t.Errorf("signed:\n want %s\n  got %s", f.signed, signed)
			}

			if f.hasMessage {
				message, err := f.buildMessage()
				if err != nil {
					t.Fatalf("message: %v", err)
				}
				if message != f.message {
					t.Errorf("message:\n want %q\n  got %q", f.message, message)
				}
			}
		})
	}
}
