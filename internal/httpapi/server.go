package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/beautifulmora/aut/internal/auth"
	"github.com/beautifulmora/aut/internal/domain"
	"github.com/beautifulmora/aut/internal/service"
	"github.com/beautifulmora/aut/pkg/redisx"
	"go.uber.org/zap"
	"net/http"
	"strings"
	"time"
)

type Server struct {
	svc    *service.Service
	tokens *auth.Service
	redis  *redisx.Client
	log    *zap.Logger
}

func New(s *service.Service, t *auth.Service, r *redisx.Client, l *zap.Logger) *Server {
	return &Server{svc: s, tokens: t, redis: r, log: l}
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.live)
	mux.HandleFunc("GET /health/ready", s.ready)
	mux.HandleFunc("POST /v1/auth/register", s.register)
	mux.HandleFunc("POST /v1/auth/login", s.login)
	mux.HandleFunc("POST /v1/auth/refresh", s.refresh)
	mux.HandleFunc("POST /v1/auth/logout", s.logout)
	mux.HandleFunc("POST /v1/auth/logout-all", s.logoutAll)
	mux.HandleFunc("GET /v1/users/me", s.me)
	return s.middleware(mux)
}
func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{"status": "ok"})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.redis.Ping(r.Context()).Err(); err != nil {
		jsonErr(w, 503, "redis unavailable")
		return
	}
	jsonOK(w, map[string]any{"status": "ready"})
}
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email     string `json:"email"`
		Username  string `json:"username"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Password  string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		jsonErr(w, 400, "invalid json")
		return
	}
	if len(in.Password) < 8 || len(in.Email) < 3 || len(in.Username) < 3 {
		jsonErr(w, 400, "invalid input")
		return
	}
	ok, err := s.redis.Allow(r.Context(), "rl:register:"+clientIP(r), 5, time.Minute)
	if err != nil || !ok {
		jsonErr(w, 429, "rate limit exceeded")
		return
	}
	pair, u, err := s.svc.Register(r.Context(), in.Email, in.Username, in.FirstName, in.LastName, in.Password)
	if err != nil {
		if errors.Is(err, domain.ErrConflict) {
			jsonErr(w, 409, "user already exists")
		} else {
			jsonErr(w, 500, "internal error")
		}
		return
	}
	jsonOK(w, map[string]any{"user": u, "tokens": pair})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if decode(r, &in) != nil {
		jsonErr(w, 400, "invalid json")
		return
	}
	ok, err := s.redis.Allow(r.Context(), "rl:login:"+clientIP(r), 10, time.Minute)
	if err != nil || !ok {
		jsonErr(w, 429, "rate limit exceeded")
		return
	}
	pair, err := s.svc.Login(r.Context(), in.Email, in.Password)
	if err != nil {
		jsonErr(w, 401, "invalid credentials")
		return
	}
	jsonOK(w, pair)
}
func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if decode(r, &in) != nil || in.RefreshToken == "" {
		jsonErr(w, 400, "invalid request")
		return
	}
	pair, err := s.svc.Refresh(r.Context(), in.RefreshToken)
	if err != nil {
		jsonErr(w, 401, "invalid refresh token")
		return
	}
	jsonOK(w, pair)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	raw, err := bearer(r)
	if err != nil {
		jsonErr(w, 401, "unauthorized")
		return
	}
	_ = s.svc.Logout(r.Context(), raw)
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) logoutAll(w http.ResponseWriter, r *http.Request) {
	id, ok := s.userID(r)
	if !ok {
		jsonErr(w, 401, "unauthorized")
		return
	}
	if err := s.svc.LogoutAll(r.Context(), id); err != nil {
		jsonErr(w, 500, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id, ok := s.userID(r)
	if !ok {
		jsonErr(w, 401, "unauthorized")
		return
	}
	u, err := s.svc.User(r.Context(), id)
	if err != nil {
		jsonErr(w, 404, "user not found")
		return
	}
	jsonOK(w, u)
}
func (s *Server) userID(r *http.Request) (string, bool) {
	v := r.Context().Value(userKey{})
	id, ok := v.(string)
	return id, ok
}
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if strings.HasPrefix(r.URL.Path, "/v1/") && r.URL.Path != "/v1/auth/register" && r.URL.Path != "/v1/auth/login" && r.URL.Path != "/v1/auth/refresh" && r.URL.Path != "/v1/auth/logout" {
			raw, err := bearer(r)
			if err != nil {
				jsonErr(w, 401, "unauthorized")
				return
			}
			id, err := s.tokens.ParseAccess(raw)
			if err != nil {
				jsonErr(w, 401, "unauthorized")
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), userKey{}, id))
		}
		next.ServeHTTP(w, r)
		s.log.Info("http request", zap.String("method", r.Method), zap.String("path", r.URL.Path), zap.Int64("duration_ms", time.Since(start).Milliseconds()))
	})
}

type userKey struct{}

func bearer(r *http.Request) (string, error) { return auth.Bearer(r.Header.Get("Authorization")) }
func decode(r *http.Request, v any) error {
	defer r.Body.Close()
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_ = json.NewEncoder(w).Encode(v)
}
func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}
func clientIP(r *http.Request) string {
	h := r.Header.Get("X-Forwarded-For")
	if h != "" {
		return strings.TrimSpace(strings.Split(h, ",")[0])
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}
