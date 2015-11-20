package v3

import (
	"encoding/hex"
	"time"
)

type Record struct {
	fields map[byte][]byte
}

func newRecord(fields map[byte][]byte) *Record {
	if fields == nil {
		fields = make(map[byte][]byte)
	}
	return &Record{fields: fields}
}

func (r *Record) UUID() string {
	return hex.EncodeToString(r.fields[uuidField])
}

func (r *Record) Title() string {
	return string(r.fields[titleField])
}

func (r *Record) Username() string {
	return string(r.fields[usernameField])
}

func (r *Record) Password() string {
	return string(r.fields[passwordField])
}

func (r *Record) Notes() string {
	return string(r.fields[notesField])
}

func (r *Record) Group() string {
	return string(r.fields[groupField])
}

func (r *Record) URL() string {
	return string(r.fields[urlField])
}

func (r *Record) Ctime() time.Time {
	return decodeTimeField(r.fields[ctimeField])
}

func (r *Record) Mtime() time.Time {
	return decodeTimeField(r.fields[mtimeField])
}

func (r *Record) Atime() time.Time {
	return decodeTimeField(r.fields[atimeField])
}
