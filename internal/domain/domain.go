package domain

import "time"

type User struct {
	ID                                   string
	Email, Username, FirstName, LastName string
	PasswordHash                         *string
	Avatar                               *string
	Active, Verified                     bool
	LastLoginAt                          *time.Time
	CreatedAt, UpdatedAt                 time.Time
}
type Identity struct {
	ID                                                    string
	UserID                                                string
	Provider, ProviderSubject, Email, DisplayName, Avatar string
	CreatedAt                                             time.Time
}
type Session struct {
	ID, UserID, TokenHash, FamilyID string
	ExpiresAt                       time.Time
	RevokedAt                       *time.Time
	CreatedAt                       time.Time
}
type TokenPair struct {
	AccessToken, RefreshToken, TokenType string
	ExpiresIn                            int64
}

var ErrNotFound = errorString("not found")
var ErrConflict = errorString("conflict")
var ErrInvalidCredentials = errorString("invalid credentials")
var ErrUnauthorized = errorString("unauthorized")

type errorString string

func (e errorString) Error() string { return string(e) }
