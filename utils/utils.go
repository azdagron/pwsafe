package utils

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/azdagron/pwsafe"
)

var (
	// Logf is the logging function and can be replaced.
	// TODO: make this pluggable on a database instance level instead of
	// globally.
	Logf = func(format string, args ...interface{}) error {
		_, err := fmt.Fprintf(os.Stderr, appendNewline(format), args...)
		return err
	}
)

// appendNewLine appends a trailing newline to a string if it does not exist
func appendNewline(s string) string {
	if len(s) > 0 && s[len(s)-1] != '\n' {
		return s + "\n"
	}
	return s
}

// LogError calls the provided function and logs any error using the Logf
// function
func LogError(fn func() error) {
	if err := fn(); err != nil {
		Logf("%s", err)
	}
}

// ReadBytes is a convenience function that returns a byte slice of size n read
// from the reader.
func ReadBytes(r io.Reader, n int) ([]byte, error) {
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	if err != nil {
		return nil, pwsafe.IOError.Wrap(err)
	}
	return p, nil
}

// SecureRandBytes is a convenience function that returns a byte slice of size n
// filled with random bytes ok for cryptographic use.
func SecureRandBytes(n int) ([]byte, error) {
	return ReadBytes(rand.Reader, n)
}
