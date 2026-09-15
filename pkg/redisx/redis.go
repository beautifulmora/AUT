package redisx

import (
	"context"
	"github.com/beautifulmora/aut/internal/config"
	"github.com/redis/go-redis/v9"
	"time"
)

type Client struct{ *redis.Client }

func Open(c config.RedisConfig) *Client {
	return &Client{redis.NewClient(&redis.Options{Addr: c.Addr, Password: c.Password, DB: c.DB})}
}
func (r *Client) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	n, err := r.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}
	if n == 1 {
		_ = r.Expire(ctx, key, window).Err()
	}
	return n <= int64(limit), nil
}
