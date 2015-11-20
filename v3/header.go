package v3

import "time"

// Header is a v3 password safe header
type Header struct {
	fields map[byte][]byte
}

// newHeader constructs an empty Header object
func newHeader(fields map[byte][]byte) *Header {
	if fields == nil {
		fields = make(map[byte][]byte)
	}
	return &Header{fields: fields}
}

// Mtime returns the timestamp of the last save on the database
func (h *Header) Mtime() time.Time {
	return decodeTimeField(h.fields[saveTimestampHeader])
}
