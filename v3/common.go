package v3

import (
	"crypto/sha256"
	"encoding/binary"
	"time"

	"golang.org/x/crypto/twofish"

	"github.com/azdagron/pwsafe"
)

var (
	Error         = pwsafe.Error
	IOError       = pwsafe.IOError
	BadPassphrase = pwsafe.BadPassphrase
	BadTag        = pwsafe.BadTag
	Corrupted     = pwsafe.Corrupted
)

const (
	hashIterations uint32 = 4096
	v3Tag                 = "PWS3"
	v3EOF                 = "PWS3-EOFPWS3-EOF"

	// Header fields
	versionHeader               byte = 0x00
	uuidHeader                  byte = 0x01
	prefsHeader                 byte = 0x02
	treeStatusHeader            byte = 0x03
	saveTimestampHeader         byte = 0x04
	whoSavedHeader              byte = 0x05
	whatSavedHeader             byte = 0x06
	lastSavedByUserHeader       byte = 0x07
	lastSavedOnHostHeader       byte = 0x08
	databaseNameHeader          byte = 0x09
	databaseDescHeader          byte = 0x0a
	databaseFilterHeader        byte = 0x0b
	reserved1Header             byte = 0x0c
	reserved2Header             byte = 0x0d
	reserved3Header             byte = 0x0e
	recentlyUsedEntriesHeader   byte = 0x0f
	namedPasswordPoliciesHeader byte = 0x10
	emptyGroupsHeader           byte = 0x11
	yubicoHeader                byte = 0x12

	// Record fields
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

	fieldEnd byte = 0xff

	saltLen = 32
	b1Len   = 16
	b2Len   = 16
	b3Len   = 16
	b4Len   = 16
	ivLen   = 16
)

func decodeTimeField(data []byte) time.Time {
	if len(data) != 4 {
		return time.Time{}
	}
	time_t := int32(binary.LittleEndian.Uint32(data))
	return time.Unix(int64(time_t), 0)
}

func makeKey(passphrase string, salt []byte, iter uint32) ([]byte, []byte) {
	h := sha256.Sum256(append([]byte(passphrase), salt...))
	for i := uint32(0); i < iter; i++ {
		h = sha256.Sum256(h[:])
	}
	phash := sha256.Sum256(h[:])
	return h[:], phash[:]
}

func alignTo(length, alignment uint32) uint32 {
	return (length + alignment - 1) / alignment * alignment
}

func rawRecordLength(data_length uint32) uint32 {
	return alignTo(recordLength(data_length), twofish.BlockSize)
}

func recordLength(data_length uint32) uint32 {
	// 4 bytes length
	// 1 byte type
	// data_length bytes data
	return 4 + 1 + data_length
}
