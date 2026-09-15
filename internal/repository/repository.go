package repository

import (
	"context"
	"errors"
	"github.com/beautifulmora/aut/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}
type Repository struct {
	DB *pgxpool.Pool
	ex executor
}

func New(db *pgxpool.Pool) *Repository { return &Repository{DB: db, ex: db} }
func (r *Repository) CreateUser(ctx context.Context, u *domain.User) error {
	_, err := r.ex.Exec(ctx, `INSERT INTO users(id,email,username,first_name,last_name,password_hash,avatar,active,verified,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)`, u.ID, u.Email, u.Username, u.FirstName, u.LastName, u.PasswordHash, u.Avatar, u.Active, u.Verified, u.CreatedAt)
	return mapErr(err)
}
func (r *Repository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return r.getUser(ctx, `SELECT id,email,username,first_name,last_name,password_hash,avatar,active,verified,last_login_at,created_at,updated_at FROM users WHERE email=$1 AND deleted_at IS NULL`, email)
}
func (r *Repository) GetUser(ctx context.Context, id string) (*domain.User, error) {
	return r.getUser(ctx, `SELECT id,email,username,first_name,last_name,password_hash,avatar,active,verified,last_login_at,created_at,updated_at FROM users WHERE id=$1 AND deleted_at IS NULL`, id)
}
func (r *Repository) getUser(ctx context.Context, q string, arg any) (*domain.User, error) {
	u := new(domain.User)
	err := r.ex.QueryRow(ctx, q, arg).Scan(&u.ID, &u.Email, &u.Username, &u.FirstName, &u.LastName, &u.PasswordHash, &u.Avatar, &u.Active, &u.Verified, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return u, err
}
func (r *Repository) TouchLogin(ctx context.Context, id string, t time.Time) error {
	_, err := r.ex.Exec(ctx, `UPDATE users SET last_login_at=$1,updated_at=$1 WHERE id=$2`, t, id)
	return err
}
func (r *Repository) CreateIdentity(ctx context.Context, i *domain.Identity) error {
	_, err := r.ex.Exec(ctx, `INSERT INTO identities(id,user_id,provider,provider_subject,email,display_name,avatar,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, i.ID, i.UserID, i.Provider, i.ProviderSubject, i.Email, i.DisplayName, i.Avatar, i.CreatedAt)
	return mapErr(err)
}
func (r *Repository) GetIdentity(ctx context.Context, p, sub string) (*domain.Identity, error) {
	i := new(domain.Identity)
	err := r.ex.QueryRow(ctx, `SELECT id,user_id,provider,provider_subject,email,display_name,avatar,created_at FROM identities WHERE provider=$1 AND provider_subject=$2`, p, sub).Scan(&i.ID, &i.UserID, &i.Provider, &i.ProviderSubject, &i.Email, &i.DisplayName, &i.Avatar, &i.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return i, err
}
func (r *Repository) CreateSession(ctx context.Context, s *domain.Session) error {
	_, err := r.ex.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,family_id,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6)`, s.ID, s.UserID, s.TokenHash, s.FamilyID, s.ExpiresAt, s.CreatedAt)
	return mapErr(err)
}
func (r *Repository) GetSessionForUpdate(ctx context.Context, hash string) (*domain.Session, error) {
	s := new(domain.Session)
	err := r.ex.QueryRow(ctx, `SELECT id,user_id,token_hash,family_id,expires_at,revoked_at,created_at FROM sessions WHERE token_hash=$1 FOR UPDATE`, hash).Scan(&s.ID, &s.UserID, &s.TokenHash, &s.FamilyID, &s.ExpiresAt, &s.RevokedAt, &s.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	return s, err
}
func (r *Repository) RevokeSession(ctx context.Context, id string, t time.Time) error {
	_, err := r.ex.Exec(ctx, `UPDATE sessions SET revoked_at=$1 WHERE id=$2 AND revoked_at IS NULL`, t, id)
	return err
}
func (r *Repository) RevokeFamily(ctx context.Context, family string, t time.Time) error {
	_, err := r.ex.Exec(ctx, `UPDATE sessions SET revoked_at=$1 WHERE family_id=$2 AND revoked_at IS NULL`, t, family)
	return err
}
func (r *Repository) RevokeUserSessions(ctx context.Context, userID string, t time.Time) error {
	_, err := r.ex.Exec(ctx, `UPDATE sessions SET revoked_at=$1 WHERE user_id=$2 AND revoked_at IS NULL`, t, userID)
	return err
}
func (r *Repository) WithTx(ctx context.Context, fn func(*Repository) error) error {
	return r.DB.BeginFunc(ctx, func(tx pgx.Tx) error { return fn(New(r.DB).withTx(tx)) })
}

type txer interface {
	Exec(context.Context, string, ...any) (pgx.Rows, error)
}

func (r *Repository) withTx(tx pgx.Tx) *Repository { return &Repository{DB: r.DB, ex: tx} }
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	return err
}
