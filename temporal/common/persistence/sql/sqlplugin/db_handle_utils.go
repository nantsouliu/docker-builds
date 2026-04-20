// The MIT License
//
// Copyright (c) 2025 Microsoft Corporation. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package sqlplugin

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

const (
	accessTokenExpiredErrorMsg = "The access token has expired"
	defaultHeartbeatInterval   = 60 * time.Second
)

var (
	heartbeatInterval = defaultHeartbeatInterval
	logger            *slog.Logger
)

func init() {
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: true,
	}))

	// AZUREML_TEMPORAL_DB_HEARTBEAT_INTERVAL should be a duration string, e.g. "60s", "1m".
	if val := os.Getenv("AZUREML_TEMPORAL_DB_HEARTBEAT_INTERVAL"); val != "" {
		if d, err := time.ParseDuration(val); err == nil && d > 0 {
			heartbeatInterval = d
			logger.Info("setting heartbeat interval from env", "interval_seconds", d.Seconds())
		} else {
			logger.Warn("invalid AZUREML_TEMPORAL_DB_HEARTBEAT_INTERVAL, using default", "value", val, "error", err)
		}
	}
	logger.Info("heartbeat interval", "interval_seconds", heartbeatInterval.Seconds())
}

func IsAccessTokenExpiredError(err error) bool {
	return err != nil && strings.Contains(err.Error(), accessTokenExpiredErrorMsg)
}

// utilis for DatabaseHandle start
func (h *DatabaseHandle) WithRetry(fn func(*sqlx.DB) error) error {
	db, err := h.DB()
	if err != nil {
		return err
	}

	err = fn(db)
	if IsAccessTokenExpiredError(err) {
		logger.Warn("access token expired, reconnecting and retrying", "error", err)
		h.reconnect(true)
		db, err = h.DB()
		if err != nil {
			return err
		}
		err = fn(db)
	}
	return err
}

func (h *DatabaseHandle) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.checkConnection(ctx)
		}
	}
}

func (h *DatabaseHandle) checkConnection(ctx context.Context) {
	db := h.db.Load()
	if db == nil {
		return
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := db.PingContext(pingCtx)

	if err != nil {
		if IsAccessTokenExpiredError(err) {
			logger.Warn("heartbeat detected expired token, reconnecting", "error", err)
			h.reconnect(true)
		} else {
			logger.Warn("heartbeat ping failed", "error", err)
		}
	}
}

// utilis for DatabaseHandle end

type tokenAuthConn struct {
	h *DatabaseHandle
}

func (c *tokenAuthConn) Rebind(query string) string {
	db, err := c.h.DB()
	if err != nil {
		return query
	}
	return db.Rebind(query)
}

func (c *tokenAuthConn) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	var res sql.Result
	err := c.h.WithRetry(func(db *sqlx.DB) error {
		var err error
		res, err = db.ExecContext(ctx, query, args...)
		return err
	})
	return res, err
}

func (c *tokenAuthConn) NamedExecContext(ctx context.Context, query string, arg interface{}) (sql.Result, error) {
	var res sql.Result
	err := c.h.WithRetry(func(db *sqlx.DB) error {
		var err error
		res, err = db.NamedExecContext(ctx, query, arg)
		return err
	})
	return res, err
}

func (c *tokenAuthConn) GetContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	return c.h.WithRetry(func(db *sqlx.DB) error {
		return db.GetContext(ctx, dest, query, args...)
	})
}

func (c *tokenAuthConn) SelectContext(ctx context.Context, dest interface{}, query string, args ...interface{}) error {
	return c.h.WithRetry(func(db *sqlx.DB) error {
		return db.SelectContext(ctx, dest, query, args...)
	})
}

func (c *tokenAuthConn) PrepareNamedContext(ctx context.Context, query string) (*sqlx.NamedStmt, error) {
	var stmt *sqlx.NamedStmt
	err := c.h.WithRetry(func(db *sqlx.DB) error {
		var err error
		stmt, err = db.PrepareNamedContext(ctx, query)
		return err
	})
	return stmt, err
}
