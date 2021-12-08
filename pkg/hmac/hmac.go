package hmac

import (
	chmac "crypto/hmac"
	"encoding/hex"
	"hash"
	"os"
	"strconv"
	"time"
)

func Equal(mac1, mac2 []byte) bool {
	return chmac.Equal(mac1, mac2)
}

type InterposedHMAC struct {
	wrapped hash.Hash
	file    *os.File
}

var _ hash.Hash = InterposedHMAC{}

func New(h func() hash.Hash, key []byte) hash.Hash {
	filename := time.Now().Format("20060102150405") + "-*.go-hmac"
	return NewWithFilePattern(filename, h, key)
}

func NewWithFilePattern(pattern string, h func() hash.Hash, key []byte) hash.Hash {
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		panic(err)
	}

	wrapped := chmac.New(h, key)

	file.Write([]byte("key: " + hex.EncodeToString(key) + "\n"))
	file.Write([]byte("size: " + strconv.Itoa(wrapped.Size()) + "\n"))
	file.Write([]byte("block size: " + strconv.Itoa(wrapped.BlockSize()) + "\n"))
	file.Write([]byte("data: "))

	return InterposedHMAC{wrapped, file}
}

func (i InterposedHMAC) Write(data []byte) (int, error) {
	i.file.Write([]byte(hex.EncodeToString(data)))
	return i.wrapped.Write(data)
}

func (i InterposedHMAC) Sum(b []byte) []byte {
	// From data
	i.file.Write([]byte("\n"))
	if b != nil {
		i.file.Write([]byte("sum(" + hex.EncodeToString(b) + "): "))
	} else {
		i.file.Write([]byte("sum(nil): "))
	}

	ret := i.wrapped.Sum(b)
	i.file.Write([]byte(hex.EncodeToString(ret) + "\n"))

	return ret
}

func (i InterposedHMAC) Reset() {
	i.file.Write([]byte("\nreset\n"))
	i.wrapped.Reset()
}

func (i InterposedHMAC) Size() int {
	return i.wrapped.Size()
}

func (i InterposedHMAC) BlockSize() int {
	return i.wrapped.BlockSize()
}
