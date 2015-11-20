package v3

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/azdagron/pwsafe/utils"
	"golang.org/x/crypto/twofish"
)

// SaveWriter writes a v3 password safe database to an io.Writer
func (db *Database) SaveWriter(w io.Writer, passphrase string) error {
	// new random values
	salt, err := utils.SecureRandBytes(saltLen)
	if err != nil {
		return err
	}

	b1, err := utils.SecureRandBytes(b1Len)
	if err != nil {
		return err
	}

	b2, err := utils.SecureRandBytes(b2Len)
	if err != nil {
		return err
	}

	b3, err := utils.SecureRandBytes(b3Len)
	if err != nil {
		return err
	}

	b4, err := utils.SecureRandBytes(b4Len)
	if err != nil {
		return err
	}

	iv, err := utils.SecureRandBytes(ivLen)
	if err != nil {
		return err
	}

	// create a digest of all the record data.
	hm := hmac.New(sha256.New, append(b3, b4...))

	var records bytes.Buffer
	if err = appendFields(hm, &records, db.header.fields); err != nil {
		return IOError.Wrap(err)
	}
	for _, record := range db.records {
		if err = appendFields(hm, &records, record.fields); err != nil {
			return IOError.Wrap(err)
		}
	}

	// generate encryption key
	pkey, phash := makeKey(passphrase, salt, hashIterations)

	// encrypt keys
	key_cipher, err := twofish.NewCipher(pkey)
	if err != nil {
		return Error.New("unable to create key cipher: %s", err)
	}

	// encrypt records
	records_cipher, err := twofish.NewCipher(append(b1, b2...))
	if err != nil {
		return Error.New("unable to create records cipher: %s", err)
	}
	records_encrypter := cipher.NewCBCEncrypter(records_cipher, iv)

	raw_records := records.Bytes()
	records_encrypter.CryptBlocks(raw_records, raw_records)

	key_cipher.Encrypt(b1, b1)
	key_cipher.Encrypt(b2, b2)
	key_cipher.Encrypt(b3, b3)
	key_cipher.Encrypt(b4, b4)

	// write it all out
	_, err = w.Write([]byte(v3Tag))
	if err != nil {
		return IOError.Wrap(err)
	}

	_, err = w.Write(salt)
	if err != nil {
		return IOError.Wrap(err)
	}

	err = binary.Write(w, binary.LittleEndian, hashIterations)
	if err != nil {
		return IOError.Wrap(err)
	}

	_, err = w.Write(phash)
	if err != nil {
		return IOError.Wrap(err)
	}

	_, err = w.Write(b1)
	if err != nil {
		return IOError.Wrap(err)
	}

	_, err = w.Write(b2)
	if err != nil {
		return IOError.Wrap(err)
	}

	_, err = w.Write(b3)
	if err != nil {
		return IOError.Wrap(err)
	}

	_, err = w.Write(b4)
	if err != nil {
		return IOError.Wrap(err)
	}

	_, err = w.Write(iv)
	if err != nil {
		return IOError.Wrap(err)
	}

	_, err = w.Write(raw_records)
	if err != nil {
		return IOError.Wrap(err)
	}

	_, err = w.Write([]byte(v3EOF))
	if err != nil {
		return IOError.Wrap(err)
	}

	_, err = w.Write(hm.Sum(nil))
	if err != nil {
		return IOError.Wrap(err)
	}

	return nil
}

func appendFields(h io.Writer, b *bytes.Buffer, fields map[byte][]byte) error {
	for field_type, field_data := range fields {
		if err := appendField(h, b, field_type, field_data); err != nil {
			return err
		}
	}
	return appendField(h, b, fieldEnd, nil)
}

func appendField(h io.Writer, b *bytes.Buffer, field_type byte,
	field_data []byte) error {

	data_len := uint32(len(field_data))
	if err := binary.Write(b, binary.LittleEndian, &data_len); err != nil {
		return err
	}
	if err := b.WriteByte(field_type); err != nil {
		return err
	}
	if _, err := io.MultiWriter(b, h).Write(field_data); err != nil {
		return err
	}
	padding := rawRecordLength(data_len) - recordLength(data_len)
	if padding > 0 {
		if _, err := io.CopyN(b, rand.Reader, int64(padding)); err != nil {
			return err
		}
	}
	return nil
}
