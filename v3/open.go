package v3

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"io/ioutil"

	"github.com/azdagron/pwsafe/utils"
	"golang.org/x/crypto/twofish"
)

// OpenReader loads a v3 database from the reader
func OpenReader(r io.Reader, passphrase_fn PassphraseFn) (
	database *Database, err error) {

	// verify the tag
	tag_bytes, err := utils.ReadBytes(r, len(v3Tag))
	if err != nil {
		return nil, err
	}
	tag := string(tag_bytes)
	if tag != v3Tag {
		return nil, BadTag.New("expected %s, got %s", v3Tag, tag)
	}

	// read in the passphrase salt and required hash iterations
	salt, err := utils.ReadBytes(r, saltLen)
	if err != nil {
		return nil, err
	}
	var iter uint32
	err = binary.Read(r, binary.LittleEndian, &iter)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	// obtain and verify the passphrase
	passphrase, err := passphrase_fn()
	if err != nil {
		return nil, Error.Wrap(err)
	}
	pkey, phash := makeKey(passphrase, salt, iter)
	expected_phash, err := utils.ReadBytes(r, sha256.Size)
	if err != nil {
		return nil, err
	}
	if string(expected_phash) != string(phash) {
		return nil, BadPassphrase.New("passphrase is incorrect")
	}

	// Read the encrypted record cipher key, encrypted hmac key, and iv
	b1, err := utils.ReadBytes(r, b1Len)
	if err != nil {
		return nil, err
	}
	b2, err := utils.ReadBytes(r, b2Len)
	if err != nil {
		return nil, err
	}

	b3, err := utils.ReadBytes(r, b3Len)
	if err != nil {
		return nil, err
	}

	b4, err := utils.ReadBytes(r, b4Len)
	if err != nil {
		return nil, err
	}

	iv, err := utils.ReadBytes(r, ivLen)
	if err != nil {
		return nil, err
	}

	// Decrypt the keys
	key_cipher, err := twofish.NewCipher(pkey)
	if err != nil {
		return nil, Error.New("unable to create key cipher: %s", err)
	}
	key_cipher.Decrypt(b1, b1)
	key_cipher.Decrypt(b2, b2)
	key_cipher.Decrypt(b3, b3)
	key_cipher.Decrypt(b4, b4)

	// Read in the encrypted records, eof marker, expected hmac value, and
	// verify the EOF marker is valid
	rest, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, IOError.New("unable to read records: %s", err)
	}
	if len(rest) < len(v3EOF)+sha256.Size {
		return nil, Error.New("not enough bytes for eof + hmac")
	}

	expected_hmac := rest[len(rest)-sha256.Size:]
	rest = rest[:len(rest)-len(expected_hmac)]
	eof := rest[len(rest)-len(v3EOF):]
	raw_records := rest[:len(rest)-len(eof)]

	if string(eof) != v3EOF {
		return nil, Corrupted.New("invalid eof marker: expected %x, got %x",
			v3EOF, eof)
	}

	// Decrypt records
	record_cipher, err := twofish.NewCipher(append(b1, b2...))
	if err != nil {
		return nil, Error.New("unable to create record cipher: %s", err)
	}
	record_decrypter := cipher.NewCBCDecrypter(record_cipher, iv)
	record_decrypter.CryptBlocks(raw_records, raw_records)

	// Read in all the fields
	r = bytes.NewReader(raw_records)
	inheader := true
	var raw_record []byte
	var header *Header
	var records []*Record
	var fields map[byte][]byte
	hm := hmac.New(sha256.New, append(b3, b4...))
	for {
		// read in the next record data length
		var data_len uint32
		err = binary.Read(r, binary.LittleEndian, &data_len)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, IOError.New("error reading record len: %s", err)
		}

		// read in the raw record data (subtracting the 4 bytes for data
		// length we already read
		raw_record_len := rawRecordLength(data_len) - 4
		if uint32(cap(raw_record)) < raw_record_len {
			raw_record = make([]byte, raw_record_len)
		}
		raw_record = raw_record[:raw_record_len]
		if _, err = io.ReadFull(r, raw_record); err != nil {
			return nil, IOError.New("unable to read record: %s", err)
		}

		data := raw_record[1 : 1+data_len]
		hm.Write(data)

		if raw_record[0] == fieldEnd {
			if inheader {
				header = newHeader(fields)
				inheader = false
			} else {
				records = append(records, newRecord(fields))
			}
			fields = nil
		} else {
			if fields == nil {
				fields = make(map[byte][]byte)
			}
			// store a copy of the record data
			fields[raw_record[0]] = append([]byte{}, data...)
		}
	}

	// Verify the record integrity
	actual_hmac := hm.Sum(nil)
	if !hmac.Equal(actual_hmac[:], expected_hmac) {
		return nil, Corrupted.New("unexpected hmac: expected %x, got %x",
			expected_hmac, actual_hmac)
	}

	return newDatabase(header, records), nil
}
