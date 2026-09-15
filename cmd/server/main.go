package main

import (
	"context"
	"errors"
	"github.com/beautifulmora/aut/internal/auth"
	"github.com/beautifulmora/aut/internal/config"
	"github.com/beautifulmora/aut/internal/httpapi"
	"github.com/beautifulmora/aut/internal/repository"
	"github.com/beautifulmora/aut/internal/service"
	"github.com/beautifulmora/aut/pkg/logger"
	"github.com/beautifulmora/aut/pkg/postgres"
	"github.com/beautifulmora/aut/pkg/redisx"
	"go.uber.org/zap"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	log := logger.New(cfg.Environment)
	defer log.Sync()
	ctx := context.Background()
	db, err := postgres.Open(ctx, cfg.DB)
	if err != nil {
		log.Fatal("postgres", zap.Error(err))
	}
	defer db.Close()
	redis := redisx.Open(cfg.Redis)
	defer redis.Close()
	if err := redis.Ping(ctx).Err(); err != nil {
		log.Fatal("redis", zap.Error(err))
	}
	repo := repository.New(db)
	tokens := auth.New(cfg.JWT)
	svc := service.New(repo, tokens)
	api := httpapi.New(svc, tokens, redis, log)
	srv := &http.Server{Addr: cfg.HTTP.Addr, Handler: api.Handler(), ReadTimeout: cfg.HTTP.ReadTimeout, WriteTimeout: cfg.HTTP.WriteTimeout, IdleTimeout: cfg.HTTP.IdleTimeout}
	go func() {
		log.Info("server started", zap.String("addr", cfg.HTTP.Addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal("http", zap.Error(err))
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}
