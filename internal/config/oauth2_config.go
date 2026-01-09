package config

import (
	"log"
	"time"

	"github.com/joho/godotenv"
)

type GoogleOAuthConfig struct {
    GOOGLE_CLIENT_ID     string
    GOOGLE_CLIENT_SECRET string
    GOOGLE_REDIRECT_URL  string
	AccessTokenTTL       time.Duration
	RefreshTokenTTL      time.Duration
}

func LoadGGConfig() *GoogleOAuthConfig {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, reading from system environment")
	}

	return &GoogleOAuthConfig{
		GOOGLE_CLIENT_ID:     getEnv("GOOGLE_CLIENT_ID", ""),
		GOOGLE_CLIENT_SECRET: getEnv("GOOGLE_CLIENT_SECRET", ""),
		GOOGLE_REDIRECT_URL:  getEnv("GOOGLE_REDIRECT_URL", ""),
		AccessTokenTTL:       15 * time.Minute,
		RefreshTokenTTL:      7 * 24 * time.Hour,
	}
}