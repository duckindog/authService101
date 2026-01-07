package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrTokenNotFound = errors.New("refresh token not found")
)

type RefreshToken struct {
	UserID    string
	TokenHash string
	ExpiresAt time.Time
}

type TokenRepository interface {
	CreateRefreshToken(ctx context.Context, userID string, tokenHash string, expiresAt time.Time) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	DeleteByTokenHash(ctx context.Context, tokenHash string) error
	DeleteByUserID(ctx context.Context, userID string) error
}

type postgresTokenRepository struct {
	db *sql.DB
}

func NewTokenRepository(db *sql.DB) TokenRepository {
	return &postgresTokenRepository{db: db}
}

func (r *postgresTokenRepository) CreateRefreshToken(ctx context.Context, userID string, tokenHash string, expiresAt time.Time) error {
	query := `
	INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
	VALUES ($1, $2, $3)
	`
	_, err := r.db.ExecContext(ctx, query, userID, tokenHash, expiresAt)
	return err
}

func (r *postgresTokenRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	var token RefreshToken
	query := `
	SELECT user_id, token_hash, expires_at FROM refresh_tokens 
	WHERE token_hash = $1 AND expires_at > now()
	`
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(&token.UserID, &token.TokenHash, &token.ExpiresAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTokenNotFound
	}

	return &token, err
}

func (r *postgresTokenRepository) DeleteByTokenHash(ctx context.Context, tokenHash string) error {
	query := `DELETE FROM refresh_tokens WHERE token_hash = $1`
	_, err := r.db.ExecContext(ctx, query, tokenHash)
	return err
}

func (r *postgresTokenRepository) DeleteByUserID(ctx context.Context, userID string) error {
	query := `DELETE FROM refresh_tokens WHERE user_id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}