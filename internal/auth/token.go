package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/beautifulmora/aut/internal/config"
	"github.com/beautifulmora/aut/internal/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"strings"
	"time"
)

type Claims struct {
	TokenType string `json:"typ"`
	jwt.RegisteredClaims
}
type Service struct{ cfg config.JWTConfig }

func New(cfg config.JWTConfig) *Service { return &Service{cfg} }
func (s *Service) Issue(userID string) (*domain.TokenPair, *domain.Session, error) {
	now := time.Now()
	jti := uuid.NewString()
	c := Claims{"access", jwt.RegisteredClaims{Issuer: s.cfg.Issuer, Audience: []string{s.cfg.Audience}, Subject: userID, ID: jti, IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.AccessTTL))}}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	raw, err := tok.SignedString([]byte(s.cfg.Secret))
	if err != nil {
		return nil, nil, err
	}
	rt, err := random(48)
	if err != nil {
		return nil, nil, err
	}
	sess := &domain.Session{ID: uuid.NewString(), UserID: userID, TokenHash: Hash(rt), FamilyID: uuid.NewString(), ExpiresAt: now.Add(s.cfg.RefreshTTL), CreatedAt: now}
	return &domain.TokenPair{AccessToken: raw, RefreshToken: rt, TokenType: "Bearer", ExpiresIn: int64(s.cfg.AccessTTL.Seconds())}, sess, nil
}
func (s *Service) ParseAccess(raw string) (string, error) {
	claims := new(Claims)
	t, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(s.cfg.Secret), nil
	}, jwt.WithIssuer(s.cfg.Issuer), jwt.WithAudience(s.cfg.Audience))
	if err != nil || !t.Valid || claims.TokenType != "access" {
		return "", domain.ErrUnauthorized
	}
	return claims.Subject, nil
}
func Hash(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func Bearer(v string) (string, error) {
	p := strings.Fields(v)
	if len(p) != 2 || !strings.EqualFold(p[0], "Bearer") {
		return "", domain.ErrUnauthorized
	}
	return p[1], nil
}
