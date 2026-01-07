package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"authService101/internal/repository"
	"authService101/internal/token"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInternal           = errors.New("internal server error")
	ErrUnauthorized       = errors.New("unauthorized")
)

type AuthService interface {
	Register(ctx context.Context, email, password string) error
	Login(ctx context.Context, email, password string) (string, string, error)
	Refresh(ctx context.Context, rawRefreshToken string) (string, string, error)
	Logout(ctx context.Context, rawRefreshToken string) error
}

type authService struct {
	userRepo   repository.UserRepository
	tokenRepo  repository.TokenRepository
	jwtManager *token.JWTManager
	refreshTTL time.Duration
}

func NewAuthService(
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	tokenManager *token.JWTManager,
	refreshTTL time.Duration,
) AuthService {
	return &authService{
		userRepo:   userRepo,
		tokenRepo:  tokenRepo,
		jwtManager: tokenManager,
		refreshTTL: refreshTTL,
	}
}

func (s *authService) Register(ctx context.Context, email, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return ErrInternal
	}

	_, err = s.userRepo.CreateUser(ctx, email, string(hash))
	if err != nil {
		if errors.Is(err, repository.ErrUserAlreadyExists) {
			return errors.New("email already in use")
		}
		return ErrInternal
	}

	return nil
}

func (s *authService) Login(ctx context.Context, email, password string) (accessToken, refreshToken string, err error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return "", "", ErrInvalidCredentials
		}
		return "", "", ErrInternal
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", "", ErrInvalidCredentials
	}

	accessToken, err = s.jwtManager.GenerateAccessToken(user.ID) // Now using userID
	if err != nil {
		return "", "", ErrInternal
	}

	rawRefresh, refreshHash, err := generateRefreshToken()
	if err != nil {
		return "", "", ErrInternal
	}

	err = s.tokenRepo.CreateRefreshToken(ctx, user.ID, refreshHash, time.Now().Add(s.refreshTTL))
	if err != nil {
		return "", "", ErrInternal
	}

	return accessToken, rawRefresh, nil
}

func (s *authService) Refresh(ctx context.Context, rawRefreshToken string) (newAccess, newRefresh string, err error) {
	hash := hashRefreshToken(rawRefreshToken)
	stored, err := s.tokenRepo.GetByTokenHash(ctx, hash)
	if err != nil {
		if errors.Is(err, repository.ErrTokenNotFound) {
			return "", "", ErrUnauthorized
		}
		return "", "", ErrInternal
	}

	newAccess, err = s.jwtManager.GenerateAccessToken(stored.UserID)
	if err != nil {
		return "", "", ErrInternal
	}

	newRawRefresh, newRefreshHash, err := generateRefreshToken()
	if err != nil {
		return "", "", ErrInternal
	}

	err = s.tokenRepo.DeleteByTokenHash(ctx, stored.TokenHash)
	if err != nil {
		return "", "", ErrInternal
	}

	err = s.tokenRepo.CreateRefreshToken(ctx, stored.UserID, newRefreshHash, time.Now().Add(s.refreshTTL))
	if err != nil {
		return "", "", ErrInternal
	}

	return newAccess, newRawRefresh, nil
}

func (s *authService) Logout(ctx context.Context, rawRefreshToken string) error {
	hash := hashRefreshToken(rawRefreshToken)
	err := s.tokenRepo.DeleteByTokenHash(ctx, hash)
	if err != nil {
		return ErrInternal
	}
	return nil
}

func generateRefreshToken() (raw string, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}

	raw = base64.RawURLEncoding.EncodeToString(b)
	hash = hashRefreshToken(raw)
	return
}

func hashRefreshToken(raw string) string {
	hashBytes := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hashBytes[:])
}
