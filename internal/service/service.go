package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"github.com/beautifulmora/aut/internal/auth"
	"github.com/beautifulmora/aut/internal/domain"
	"github.com/beautifulmora/aut/internal/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"strings"
	"time"
)

type Service struct {
	repo   *repository.Repository
	tokens *auth.Service
}

func New(r *repository.Repository, t *auth.Service) *Service { return &Service{r, t} }
func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(h)), nil
}
func verifyPassword(password, encoded string) bool {
	p := strings.Split(encoded, "$")
	if len(p) != 6 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(p[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(p[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
func (s *Service) Register(ctx context.Context, email, user, first, last, password string) (*domain.TokenPair, *domain.User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	user = strings.ToLower(strings.TrimSpace(user))
	ph, err := hashPassword(password)
	if err != nil {
		return nil, nil, err
	}
	u := &domain.User{ID: uuid.NewString(), Email: email, Username: user, FirstName: first, LastName: last, PasswordHash: &ph, Active: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := s.repo.CreateUser(ctx, u); err != nil {
		return nil, nil, domain.ErrConflict
	}
	pair, sess, err := s.tokens.Issue(u.ID)
	if err != nil {
		return nil, nil, err
	}
	if err := s.repo.CreateSession(ctx, sess); err != nil {
		return nil, nil, err
	}
	return pair, u, nil
}
func (s *Service) Login(ctx context.Context, email, password string) (*domain.TokenPair, error) {
	u, err := s.repo.GetUserByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if err != nil || u.PasswordHash == nil || !u.Active {
		return nil, domain.ErrInvalidCredentials
	}
	if !verifyPassword(password, *u.PasswordHash) {
		return nil, domain.ErrInvalidCredentials
	}
	pair, sess, err := s.tokens.Issue(u.ID)
	if err != nil {
		return nil, err
	}
	if err = s.repo.CreateSession(ctx, sess); err != nil {
		return nil, err
	}
	_ = s.repo.TouchLogin(ctx, u.ID, time.Now())
	return pair, nil
}
func (s *Service) Refresh(ctx context.Context, raw string) (*domain.TokenPair, error) {
	h := auth.Hash(raw)
	var out *domain.TokenPair
	err := s.repo.WithTx(ctx, func(r *repository.Repository) error {
		sess, err := r.GetSessionForUpdate(ctx, h)
		if err != nil {
			return domain.ErrUnauthorized
		}
		if sess.RevokedAt != nil || time.Now().After(sess.ExpiresAt) {
			if sess.RevokedAt != nil {
				return r.RevokeFamily(ctx, sess.FamilyID, time.Now())
			}
			return domain.ErrUnauthorized
		}
		u, err := r.GetUser(ctx, sess.UserID)
		if err != nil || !u.Active {
			return domain.ErrUnauthorized
		}
		now := time.Now()
		if err = r.RevokeSession(ctx, sess.ID, now); err != nil {
			return err
		}
		pair, next, err := s.tokens.Issue(u.ID)
		if err != nil {
			return err
		}
		next.FamilyID = sess.FamilyID
		if err = r.CreateSession(ctx, next); err != nil {
			return err
		}
		out = pair
		return nil
	})
	return out, err
}
func (s *Service) Logout(ctx context.Context, raw string) error {
	return s.repo.RevokeSession(ctx, auth.Hash(raw), time.Now())
}
func (s *Service) LogoutAll(ctx context.Context, userID string) error {
	return s.repo.RevokeUserSessions(ctx, userID, time.Now())
}
func (s *Service) User(ctx context.Context, id string) (*domain.User, error) {
	return s.repo.GetUser(ctx, id)
}
