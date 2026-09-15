package postgres

import (
	"context"
	"github.com/beautifulmora/aut/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Open(ctx context.Context, c config.DBConfig) (*pgxpool.Pool, error) {
	pc, err := pgxpool.ParseConfig(c.URL)
	if err != nil {
		return nil, err
	}
	pc.MaxConns = int32(c.MaxConns)
	pc.MinConns = int32(c.MinConns)
	pc.MaxConnLifetime = c.MaxConnLifetime
	pc.MaxConnIdleTime = c.MaxConnIdle
	return pgxpool.NewWithConfig(ctx, pc)
}
