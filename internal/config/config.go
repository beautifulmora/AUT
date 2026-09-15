package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTP        HTTPConfig
	DB          DBConfig
	Redis       RedisConfig
	JWT         JWTConfig
	OAuth       OAuthConfig
	Environment string
}
type HTTPConfig struct {
	Addr                                   string
	ReadTimeout, WriteTimeout, IdleTimeout time.Duration
}
type DBConfig struct {
	URL                          string
	MaxConns, MinConns           int
	MaxConnLifetime, MaxConnIdle time.Duration
}
type RedisConfig struct {
	Addr, Password string
	DB             int
}
type JWTConfig struct {
	Secret, Issuer, Audience string
	AccessTTL, RefreshTTL    time.Duration
}
type OAuthConfig struct {
	Google OAuthProvider
	GitHub OAuthProvider
}
type OAuthProvider struct{ ClientID, ClientSecret, RedirectURL string }

func Load() (Config, error) {
	c := Config{Environment: env("ENVIRONMENT", "development"), HTTP: HTTPConfig{Addr: env("HTTP_ADDR", ":8080"), ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}, DB: DBConfig{URL: os.Getenv("DATABASE_URL"), MaxConns: parseInt("DB_MAX_CONNS", 20), MinConns: parseInt("DB_MIN_CONNS", 2), MaxConnLifetime: time.Hour, MaxConnIdle: 30 * time.Minute}, Redis: RedisConfig{Addr: env("REDIS_ADDR", "localhost:6379"), Password: os.Getenv("REDIS_PASSWORD"), DB: parseInt("REDIS_DB", 0)}, JWT: JWTConfig{Secret: os.Getenv("JWT_SECRET"), Issuer: env("JWT_ISSUER", "aut"), Audience: env("JWT_AUDIENCE", "aut-api"), AccessTTL: 15 * time.Minute, RefreshTTL: 30 * 24 * time.Hour}, OAuth: OAuthConfig{Google: OAuthProvider{ClientID: os.Getenv("GOOGLE_CLIENT_ID"), ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"), RedirectURL: os.Getenv("GOOGLE_REDIRECT_URL")}, GitHub: OAuthProvider{ClientID: os.Getenv("GITHUB_CLIENT_ID"), ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"), RedirectURL: os.Getenv("GITHUB_REDIRECT_URL")}}}
	if c.DB.URL == "" {
		return c, fmt.Errorf("DATABASE_URL is required")
	}
	if len(c.JWT.Secret) < 32 {
		return c, fmt.Errorf("JWT_SECRET must be at least 32 bytes")
	}
	return c, nil
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func parseInt(k string, d int) int {
	v, err := strconv.Atoi(env(k, strconv.Itoa(d)))
	if err != nil {
		return d
	}
	return v
}
