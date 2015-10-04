package pwsafe

import (
	"fmt"
	"io"
	"os"

	"github.com/spacemonkeygo/errors"
)

var (
	Error             = errors.NewClass("db error")
	IOError           = Error.NewClass("io error")
	InvalidPassphrase = Error.NewClass("invalid passphrase")
)

func logError(fn func() error) {
	err := fn()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
	}
}

func readBytes(r io.Reader, n int) ([]byte, error) {
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	if err != nil {
		return nil, IOError.Wrap(err)
	}
	return p, nil
}
