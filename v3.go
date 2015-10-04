package pwsafe

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"io/ioutil"
	"time"

	"golang.org/x/crypto/twofish"
)

const (
	uuidField             byte = 0x01
	groupField            byte = 0x02
	titleField            byte = 0x03
	usernameField         byte = 0x04
	notesField            byte = 0x05
	passwordField         byte = 0x06
	ctimeField            byte = 0x07
	passwordMtimeField    byte = 0x08
	atimeField            byte = 0x09
	expiryField           byte = 0x0a
	reserved01Field       byte = 0x0b
	mtimeField            byte = 0x0c
	urlField              byte = 0x0d
	autotypeField         byte = 0x0e
	historyField          byte = 0x0f
	policyField           byte = 0x10
	expiryIntervalField   byte = 0x11
	runCommandField       byte = 0x12
	dblClickField         byte = 0x13
	emailField            byte = 0x14
	protectedEntryField   byte = 0x15
	passwordSymField      byte = 0x16
	shiftDblclickField    byte = 0x17
	policyNameField       byte = 0x18
	keyboardShortcutField byte = 0x19
	endField              byte = 0xff
)

func loadV3(r io.Reader, passphrase string) (records []Record, err error) {
	salt, err := readBytes(r, 32)
	if err != nil {
		return nil, err
	}

	var iter uint32
	err = binary.Read(r, binary.LittleEndian, &iter)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	pkey, phash := makeKey(passphrase, salt, iter)

	expected_phash, err := readBytes(r, 32)
	if err != nil {
		return nil, err
	}

	if string(expected_phash) != string(phash) {
		return nil, InvalidPassphrase.New("passphrase is incorrect")
	}

	b1, err := readBytes(r, 16)
	if err != nil {
		return nil, err
	}

	b2, err := readBytes(r, 16)
	if err != nil {
		return nil, err
	}

	b3, err := readBytes(r, 16)
	if err != nil {
		return nil, err
	}

	b4, err := readBytes(r, 16)
	if err != nil {
		return nil, err
	}

	iv, err := readBytes(r, 16)
	if err != nil {
		return nil, err
	}

	twof, err := twofish.NewCipher(pkey)
	if err != nil {
		return nil, Error.New("unable to create twofish cipher: %s", err)
	}

	twof.Decrypt(b1, b1)
	twof.Decrypt(b2, b2)
	twof.Decrypt(b3, b3)
	twof.Decrypt(b4, b4)

	rest, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, Error.New("unable to read records: %s", err)
	}

	const expectedEof = "PWS3-EOFPWS3-EOF"
	if len(rest) < len(expectedEof)+sha256.Size {
		return nil, Error.New("not enough bytes for eof + hmac")
	}

	expected_hmac := rest[len(rest)-sha256.Size:]
	rest = rest[:len(rest)-len(expected_hmac)]
	eof := rest[len(rest)-len(expectedEof):]
	raw_records := rest[:len(rest)-len(eof)]

	if string(eof) != expectedEof {
		return nil, Error.New("invalid eof marker: expected %x, got %x",
			expectedEof, eof)
	}

	twof, err = twofish.NewCipher(append(b1, b2...))
	if err != nil {
		return nil, Error.New("unable to create twofish cipher: %s", err)
	}

	decrypter := cipher.NewCBCDecrypter(twof, iv)
	decrypter.CryptBlocks(raw_records, raw_records)

	hm := hmac.New(sha256.New, append(b3, b4...))

	r = bytes.NewReader(raw_records)
	// all records at least one block long, so start with that
	inheader := true
	var raw_record []byte

	var record Record
	for {
		var data_len uint32
		err = binary.Read(r, binary.LittleEndian, &data_len)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, Error.New("error reading record len: %s", err)
		}
		// read in the reset of the record data
		record_len := (4 + 1 + data_len)
		if record_len%twofish.BlockSize != 0 {
			record_len = (record_len + twofish.BlockSize) / twofish.BlockSize *
				twofish.BlockSize
		}

		// adjust for length bytes that have already been read
		record_len -= 4

		if uint32(cap(raw_record)) < record_len {
			raw_record = make([]byte, record_len)
		}
		raw_record = raw_record[:record_len]
		if _, err = io.ReadFull(r, raw_record); err != nil {
			return nil, IOError.New("unable to read record: %s", err)
		}

		data := raw_record[1 : data_len+1]
		hm.Write(data)

		if inheader {
			switch raw_record[0] {
			case 0x00:
			case 0x01:
			case 0x02:
			case 0x03:
			case 0x04:
			case 0x05:
			case 0x06:
			case 0x07:
			case 0x08:
			case 0x09:
			case 0x0a:
			case 0x0b:
			case 0x0c:
			case 0x0d:
			case 0x0e:
			case 0x0f:
			case 0x10:
			case 0x11:
			case 0x12:
			case 0xff:
				inheader = false
			}
		} else {
			switch raw_record[0] {
			case uuidField:
				record.UUID = hex.EncodeToString(data)
			case groupField:
				record.Group = string(data)
			case titleField:
				record.Title = string(data)
			case usernameField:
				record.Username = string(data)
			case notesField:
				record.Notes = string(data)
			case passwordField:
				record.Password = string(data)
			case ctimeField:
				record.Ctime = decodeTimeField(data)
			case passwordMtimeField:
			case atimeField:
				record.Atime = decodeTimeField(data)
			case expiryField:
			case reserved01Field:
			case mtimeField:
				record.Mtime = decodeTimeField(data)
			case urlField:
				record.URL = string(data)
			case autotypeField:
			case historyField:
			case policyField:
			case expiryIntervalField:
			case runCommandField:
			case dblClickField:
			case emailField:
			case protectedEntryField:
			case passwordSymField:
			case shiftDblclickField:
			case policyNameField:
			case keyboardShortcutField:
			case endField:
				records = append(records, record)
				record = Record{}
			}
		}
	}

	actual_hmac := hm.Sum(nil)
	if !hmac.Equal(actual_hmac[:], expected_hmac) {
		return nil, Error.New("unexpected hmac: expected %x, got %x",
			expected_hmac, actual_hmac)
	}

	return records, nil
}

func makeKey(passphrase string, salt []byte, iter uint32) ([]byte, []byte) {
	h := sha256.Sum256(append([]byte(passphrase), salt...))
	for i := uint32(0); i < iter; i++ {
		h = sha256.Sum256(h[:])
	}
	phash := sha256.Sum256(h[:])
	return h[:], phash[:]
}

func decodeTimeField(data []byte) time.Time {
	if len(data) != 4 {
		return time.Time{}
	}
	time_t := int32(binary.LittleEndian.Uint32(data))
	return time.Unix(int64(time_t), 0)
}

func saveV3(w io.Writer) error {
	return nil
}
