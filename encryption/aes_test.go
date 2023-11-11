package encryption

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestEncryptionSampleCase(t *testing.T) {
	key := []uint8{0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00}
	message := []uint8{0x00, 0x00, 0x01, 0x01,
		0x03, 0x03, 0x07, 0x07,
		0x0f, 0x0f, 0x1f, 0x1f,
		0x3f, 0x3f, 0x7f, 0x7f}
	stringMessage := string(message)
	got := EncryptAES_128(stringMessage, key)
	want := []uint8{0xc7, 0xd1, 0x24, 0x19,
		0x48, 0x9e, 0x3b, 0x62,
		0x33, 0xa2, 0xc5, 0xa7,
		0xf4, 0x56, 0x31, 0x72}

	if !equal(got, want) {
		t.Errorf("got %x\n want %x\n", got, want)
	}
}

func TestDecryptionSampleCase(t *testing.T) {
	key := []uint8{0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00}
	message := []uint8{0xc7, 0xd1, 0x24, 0x19,
		0x48, 0x9e, 0x3b, 0x62,
		0x33, 0xa2, 0xc5, 0xa7,
		0xf4, 0x56, 0x31, 0x72}
	got := DecryptAES_128(message, key)
	want := []uint8{0x00, 0x00, 0x01, 0x01,
		0x03, 0x03, 0x07, 0x07,
		0x0f, 0x0f, 0x1f, 0x1f,
		0x3f, 0x3f, 0x7f, 0x7f}

	if !equal([]uint8(got), want) {
		t.Errorf("got %x\n want %x\n", got, want)
	}
}

func TestEncryptionDecryption(t *testing.T) {
	for i := 0; i < 100; i++ {
		key, _ := generateRandomKey()
		for j := 0; j < 100; j++ {
			msgSize, _ := rand.Int(rand.Reader, big.NewInt(500))
			msgSizeInt := int(msgSize.Int64())
			message, _ := generateRandomString(msgSizeInt)

			encryptedMessage := EncryptAES_128(message, key)
			decryptedMessage := DecryptAES_128(encryptedMessage, key)
			if !equal([]uint8(decryptedMessage), []uint8(message)) {
				t.Errorf("got %x\n want %x\n", []uint8(decryptedMessage), []uint8(message))
			}
		}
	}
}

func BenchmarkEncryption(b *testing.B) {
	key, _ := generateRandomKey()
	message, _ := generateRandomString(10000)
	for n := 0; n < b.N; n++ {
		EncryptAES_128(message, key)
	}
}

func equal(got, want []uint8) bool {
	if len(got) > len(want) {
		difference := len(got) - len(want)
		for i := 0; i < difference; i++ {
			if got[i] != 0 {
				return false
			}
		}
		return equal(got[difference:], want) // Removing padding, trying again
	} else if len(got) < len(want) {
		return false
	} else {
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
	}
	return true
}

func generateRandomString(length int) (string, error) {
	// Determine the number of random bytes needed based on the desired string length.
	bytes := make([]byte, (length+1)/2) // +1 to round up for odd lengths

	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Encode the random bytes to a string using base64 encoding.
	randomString := base64.URLEncoding.EncodeToString(bytes)

	// Trim any padding characters (=) from the end.
	// randomString = randomString[:length]

	return randomString, nil
}

func generateRandomKey() ([]uint8, error) {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}

	// Convert bytes to a slice of uint8.
	uint8Slice := make([]uint8, 16)
	for i, b := range bytes {
		uint8Slice[i] = b
	}

	return uint8Slice, nil
}
