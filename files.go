package common

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
)

type Hasher struct {
	h hash.Hash
}

func NewHasher() *Hasher {
	return &Hasher{h: sha256.New()}
}

func (h *Hasher) Write(p []byte) (int, error) {
	return h.h.Write(p)
}

func (h *Hasher) Sum() string {
	return hex.EncodeToString(h.h.Sum(nil))
}

func Sha256OfFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	stat, _ := f.Stat()
	h := sha256.New()
	_, err = io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), stat.Size(), nil
}
