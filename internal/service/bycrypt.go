package service

import (
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/bcrypt"
)

// HS256 signs data using HMAC-SHA256
func Sign(data string, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func GenerateFromPassword(password []byte, cost int) ([]byte, error) {
	return bcrypt.GenerateFromPassword(password, cost)
}

func CompareHashAndPassword(hashedPassword, password []byte) error {
	return bcrypt.CompareHashAndPassword(hashedPassword, password)
}

// Verify checks if the signature matches the data + secret
func Verify(data string, secret, signature []byte) bool {
	expected := Sign(data, secret)
	return hmac.Equal(expected, signature)
}
