package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
)

type Claims struct {
	UserID string `json:"sub"`
	jwt.RegisteredClaims
}

type JWTManager struct {
	secretKey      []byte
	issuer         string
	accessTokenTTL time.Duration
}

func NewJWTManager(
	secret string,
	issuer string,
	accessTokenTTL time.Duration,
) *JWTManager {
	return &JWTManager{
		secretKey:      []byte(secret),
		issuer:         issuer,
		accessTokenTTL: accessTokenTTL,
	}
}

func (j *JWTManager) GenerateAccessToken(userID string) (string, error) {
	now := time.Now()

	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.accessTokenTTL)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secretKey)
}


func (j *JWTManager) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrInvalidToken
			}
			return j.secretKey, nil
		},
	)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims.Issuer != j.issuer {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

