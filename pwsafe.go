package pwsafe

import (
	"encoding/hex"
	"io"
	"os"
	"time"
)

type PassphraseFn func() (string, error)

type Record struct {
	UUID     string
	Title    string
	Username string
	Password string
	Notes    string
	Group    string
	URL      string
	Ctime    time.Time
	Mtime    time.Time
	Atime    time.Time
}

type DB struct {
	records []Record
}

func New(passphrase_callback PassphraseFn) *DB {
	return &DB{}
}

func Load(path string, passphrase_fn PassphraseFn) (db *DB, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer logError(f.Close)

	// read in the tag
	tag := make([]byte, 4)
	_, err = io.ReadFull(f, tag)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	passphrase, err := passphrase_fn()
	if err != nil {
		return nil, err
	}

	db = &DB{}
	switch string(tag) {
	case "PWS3":
		db.records, err = loadV3(f, passphrase)
	default:
		return nil, Error.New("unrecognized tag: %s", hex.Dump(tag))
	}
	if err != nil {
		return nil, err
	}
	return db, nil
}

func (db *DB) Save(path string) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return nil
	}
	defer logError(f.Close)
	// always save as the latest
	return saveV3(f)
}

func (db *DB) Records() []Record {
	return append([]Record(nil), db.records...)
}
