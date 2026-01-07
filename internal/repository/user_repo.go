package repository

import (
	"context"
	"database/sql"
	"errors"

	"authService101/internal/model"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
)

type UserRepository interface {
	CreateUser(ctx context.Context, email, passwordHash string) (string, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	GetByID(ctx context.Context, id string) (*model.User, error)
}

type postgresUserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
	return &postgresUserRepository{db: db}
}

func (r *postgresUserRepository) CreateUser(ctx context.Context, email, passwordHash string) (string, error) {
	query := `
	INSERT INTO users (email, password_hash)
	VALUES ($1, $2)
	RETURNING id
	`

	var id string
	err := r.db.QueryRowContext(ctx, query, email, passwordHash).Scan(&id)
	if err != nil {
		return "", errors.New("error while creating User")
	}

	return id, nil
}

func (r *postgresUserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User
	query := `SELECT id, email, password_hash, is_active, created_at FROM users WHERE email = $1`
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.IsActive, &user.CreatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}

	return &user, err
}

func (r *postgresUserRepository) GetByID(ctx context.Context, id string) (*model.User, error) {
	var user model.User
	query := `SELECT id, email, password_hash, is_active, created_at FROM users WHERE id = $1`
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.IsActive, &user.CreatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}

	return &user, err
}
