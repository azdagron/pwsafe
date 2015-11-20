package v3

import (
	"os"

	"github.com/azdagron/pwsafe"
	"github.com/azdagron/pwsafe/utils"
)

// Database is a v3 password safe database
type Database struct {
	header  *Header
	records []*Record
}

// newDatabase returns a new database object with the specified header and
// records.
func newDatabase(header *Header, records []*Record) *Database {
	return &Database{
		header:  header,
		records: records,
	}
}

// PassphraseFn is a callback to retrieve the password when opening a database.
type PassphraseFn func() (string, error)

// Open opens a v3 password safe database
func Open(path string, passphrase_fn PassphraseFn) (
	database pwsafe.Database, err error) {

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer utils.LogError(f.Close)

	return OpenReader(f, passphrase_fn)
}

// Save saves the database to the path
func (db *Database) Save(path, passphrase string) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return nil
	}
	defer utils.LogError(f.Close)

	// always save as the latest
	return db.SaveWriter(f, passphrase)
}

// Version returns the database version
func (db *Database) Version() string {
	return "v3"
}

// Header returns the database header
func (db *Database) Header() pwsafe.Header {
	return db.header
}

// Records returns the database records
func (db *Database) Records() []pwsafe.Record {
	// Convert between the concrete implementation slice and the interface
	// slice. If only go could do this implicitly.
	records := make([]pwsafe.Record, 0, len(db.records))
	for _, record := range db.records {
		records = append(records, record)
	}
	return records
}
