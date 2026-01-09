package service

import (
	"context"
	"errors"
	"time"
	"net/http"
	"encoding/json"
	"net/url"

	"authService101/internal/config"
	"authService101/internal/model"
	"authService101/internal/repository"
	"authService101/internal/token"
	"log"
)


type OAuth2Service interface {
	GGRegister(ctx context.Context, code string) error
	GGLogin(ctx context.Context, code string) (string, string, string, error)
	GGRefresh(ctx context.Context, rawRefreshToken string) (string, string, error)
	GGLogout(ctx context.Context, rawRefreshToken string) error
}

type oauth2Service struct {
	userRepo   repository.UserRepository
	tokenRepo repository.TokenRepository
	jwtManager *token.JWTManager
	refreshTTL time.Duration	
	cfg        *config.GoogleOAuthConfig
}

func NewOAuth2Service(userRepo repository.UserRepository, tokenRepo repository.TokenRepository, jwtManager *token.JWTManager, refreshTTL time.Duration, cfg *config.GoogleOAuthConfig) OAuth2Service {
	return &oauth2Service{
		userRepo: userRepo,
		tokenRepo: tokenRepo,
		jwtManager: jwtManager,
		refreshTTL: refreshTTL,
		cfg: cfg,
	}
}

func (s *oauth2Service) GGRegister(ctx context.Context, code string) error {
	token, err := s.exchangeCode(ctx, code)
	if err != nil {
		return err
	}
	
	user, err := s.verifyIDToken(ctx, token.IDToken)
	if err != nil {
		return err
	}
	
	_, err = s.userRepo.CreateUser(ctx, user.Name, user.Name)
	return err
}

func (s *oauth2Service) GGLogin(ctx context.Context, code string) (accessToken, refreshToken, email string, err error) {
	token, err := s.exchangeCode(ctx, code)
	if err != nil {
		log.Printf("GGLogin: exchangeCode error: %v", err)
		return "", "", "", err
	}
	
	user, err := s.verifyIDToken(ctx, token.IDToken)
	if err != nil {
		log.Printf("GGLogin: verifyIDToken error: %v", err)
		return "", "", "", err
	}
	
	dbUser, err := s.userRepo.GetByUser(ctx, user.Email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			// Auto-register
			_, err = s.userRepo.CreateUser(ctx, user.Email, "google-auth-no-password")
			if err != nil {
				log.Printf("GGLogin: CreateUser error: %v", err)
				return "", "", "", ErrInternal
			}
			dbUser, err = s.userRepo.GetByUser(ctx, user.Email)
			if err != nil {
				log.Printf("GGLogin: GetByUser (after create) error: %v", err)
				return "", "", "", ErrInternal
			}
		} else {
			log.Printf("GGLogin: GetByUser error: %v", err)
			return "", "", "", ErrInternal
		}
	}

	accessToken, err = s.jwtManager.GenerateAccessToken(dbUser.ID)
	if err != nil {
		log.Printf("GGLogin: GenerateAccessToken error: %v", err)
		return "", "", "", ErrInternal
	}

	rawRefresh, refreshHash, err := generateRefreshToken()
	if err != nil {
		log.Printf("GGLogin: generateRefreshToken error: %v", err)
		return "", "", "", ErrInternal
	}

	err = s.tokenRepo.CreateRefreshToken(ctx, dbUser.ID, refreshHash, time.Now().Add(s.refreshTTL))
	if err != nil {
		log.Printf("GGLogin: CreateRefreshToken error: %v", err)
		return "", "", "", ErrInternal
	}

	return accessToken, rawRefresh, dbUser.Name, nil
}

func (s *oauth2Service) GGRefresh(ctx context.Context, rawRefreshToken string) (newAccess, newRefresh string, err error) {
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

func (s *oauth2Service) GGLogout(ctx context.Context, rawRefreshToken string) error {
	hash := hashRefreshToken(rawRefreshToken)
	err := s.tokenRepo.DeleteByTokenHash(ctx, hash)
	if err != nil {
		return ErrInternal
	}
	return nil
}

func (s *oauth2Service) exchangeCode(ctx context.Context, code string) (*model.GGToken, error) {
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", s.cfg.GOOGLE_CLIENT_ID)
	form.Set("client_secret", s.cfg.GOOGLE_CLIENT_SECRET)
	form.Set("redirect_uri", s.cfg.GOOGLE_REDIRECT_URL)
	form.Set("grant_type", "authorization_code")

	resp, err := http.PostForm("https://oauth2.googleapis.com/token", form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errData map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errData)
		log.Printf("exchangeCode: non-200 status: %d, body: %v", resp.StatusCode, errData)
		return nil, errors.New("failed to exchange code")
	}

	var token model.GGToken
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}

	return &token, nil
}

func (s *oauth2Service) verifyIDToken(ctx context.Context, idToken string) (*model.GGUser, error) {
	resp, err := http.Get("https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=" + idToken)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errData map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errData)
		log.Printf("verifyIDToken: non-200 status: %d, body: %v", resp.StatusCode, errData)
		return nil, errors.New("failed to verify id token")
	}

	var user model.GGUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}