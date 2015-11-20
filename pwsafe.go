package pwsafe

import (
	"time"

	"github.com/spacemonkeygo/errors"
)

var (
	// Error is a generic error class for pwsafe.
	Error = errors.NewClass("pwsafe")

	// IOError represents an io error.
	IOError = Error.NewClass("io error")

	// BadPassphrase indicates that the passphrase was bad.
	BadPassphrase = Error.NewClass("bad passphrase", errors.NoCaptureStack())

	// BadTag indicates that the tag on the database file is unexpected.
	BadTag = Error.NewClass("bad tag", errors.NoCaptureStack())

	// Corrupted indicates that the database has been corrupted.
	Corrupted = Error.NewClass("corrupted", errors.NoCaptureStack())
)

// Database represents a pwsafe database.
type Database interface {

	// Version returns a version string for the database.
	Version() string

	// Header returns the database header.
	Header() Header

	// Records returns the database records.
	Records() []Record

	// Save saves the database to the path.
	Save(path, passphrase string) error
}

// Record represents a database record.
type Record interface {
	UUID() string
	Title() string
	Username() string
	Password() string
	Notes() string
	Group() string
	URL() string
	Ctime() time.Time
	Mtime() time.Time
	Atime() time.Time
}

// Header represents a database header.
type Header interface {
	Mtime() time.Time
}
