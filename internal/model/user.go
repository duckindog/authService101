package model

import (
	"time"
)

type User struct {
	ID           string    `json:"id"`
	Name        string    `json:"name"`
	PasswordHash string    `json:"-"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
}

type RegisterRequest struct {
	Name    string `json:"name"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Name    string `json:"name"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Email        string `json:"email,omitempty"`
}

type GGCode struct { 
	Code string `json:"code"`
	ClientID string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI string `json:"redirect_uri"`
	GrantType string `json:"grant_type"`
}

type GGToken struct { 
	AccessToken string `json:"access_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken string `json:"id_token"`
}

type GGUser struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified interface{} `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}