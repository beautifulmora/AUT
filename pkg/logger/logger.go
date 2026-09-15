package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func New(env string) *zap.Logger {
	cfg := zap.NewProductionConfig()
	if env == "development" {
		cfg.Development = true
		cfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	}
	l, _ := cfg.Build()
	return l
}
