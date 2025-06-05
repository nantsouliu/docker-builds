// The MIT License
//
// Copyright (c) 2020 Temporal Technologies Inc.  All rights reserved.
//
// Copyright (c) 2020 Uber Technologies, Inc.
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

package session

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/iancoleman/strcase"
	"github.com/jmoiron/sqlx"
	"go.temporal.io/server/common/config"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/log/tag"
	"go.temporal.io/server/common/persistence/sql/sqlplugin/postgresql/driver"
	"go.temporal.io/server/common/resolver"
)

const (
	dsnFmt = "postgres://%v:%v@%v/%v?%v"
)

const (
	sslMode        = "sslmode"
	sslModeNoop    = "disable"
	sslModeRequire = "require"
	sslModeFull    = "verify-full"

	sslCA   = "sslrootcert"
	sslKey  = "sslkey"
	sslCert = "sslcert"
)

type Session struct {
	*sqlx.DB
}

func NewSession(
	cfg *config.SQL,
	d driver.Driver,
	resolver resolver.ServiceResolver,
	cred *azidentity.DefaultAzureCredential,
	logger log.Logger,
) (*Session, error) {
	db, err := createConnection(cfg, d, resolver, cred, logger)
	if err != nil {
		return nil, err
	}
	return &Session{DB: db}, nil
}

func (s *Session) Close() {
	if s.DB != nil {
		_ = s.DB.Close()
	}
}

func createConnection(
	cfg *config.SQL,
	d driver.Driver,
	resolver resolver.ServiceResolver,
	cred *azidentity.DefaultAzureCredential,
	logger log.Logger,
) (*sqlx.DB, error) {
	dsn, err := buildDSN(cfg, resolver, cred, logger)
	if err != nil {
		return nil, err
	}
	db, err := d.CreateConnection(dsn)
	if err != nil {
		return nil, err
	}
	if cfg.MaxConns > 0 {
		db.SetMaxOpenConns(cfg.MaxConns)
	}
	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.MaxConnLifetime > 0 {
		db.SetConnMaxLifetime(cfg.MaxConnLifetime)
	}

	// Maps struct names in CamelCase to snake without need for db struct tags.
	db.MapperFunc(strcase.ToSnake)
	return db, nil
}

func buildDSN(
	cfg *config.SQL,
	r resolver.ServiceResolver,
	cred *azidentity.DefaultAzureCredential,
	logger log.Logger,
) (string, error) {
	tlsAttrs := buildDSNAttr(cfg).Encode()
	resolvedAddr := r.Resolve(cfg.ConnectAddr)[0]

	var passwd string
	var err error = nil

	if !cfg.EnableEntraAuth || cred == nil {
		passwd = url.QueryEscape(cfg.Password)
	} else {
		token, err := getAccessTokenWithRetry(
			cred,
			cfg.EntraScope,
			3,
			logger,
		)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to get access token for %v: %v", cfg.ConnectAddr, err), tag.Error(err))
		}
		passwd = token
	}

	dsn := fmt.Sprintf(
		dsnFmt,
		cfg.User,
		passwd,
		resolvedAddr,
		cfg.DatabaseName,
		tlsAttrs,
	)

	return dsn, err
}

func buildDSNAttr(cfg *config.SQL) url.Values {
	parameters := url.Values{}
	if cfg.TLS != nil && cfg.TLS.Enabled {
		if !cfg.TLS.EnableHostVerification {
			parameters.Set(sslMode, sslModeRequire)
		} else {
			parameters.Set(sslMode, sslModeFull)
		}

		if cfg.TLS.CaFile != "" {
			parameters.Set(sslCA, cfg.TLS.CaFile)
		}
		if cfg.TLS.KeyFile != "" && cfg.TLS.CertFile != "" {
			parameters.Set(sslKey, cfg.TLS.KeyFile)
			parameters.Set(sslCert, cfg.TLS.CertFile)
		}
	} else {
		parameters.Set(sslMode, sslModeNoop)
	}

	for k, v := range cfg.ConnectAttributes {
		key := strings.TrimSpace(k)
		value := strings.TrimSpace(v)
		if parameters.Get(key) != "" {
			panic(fmt.Sprintf("duplicate connection attr: %v:%v, %v:%v",
				key,
				parameters.Get(key),
				key, value,
			))
		}
		parameters.Set(key, value)
	}
	return parameters
}

func getAccessTokenWithRetry(cred *azidentity.DefaultAzureCredential, scope string, maxRetry int, logger log.Logger) (string, error) {
	if maxRetry <= 0 {
		maxRetry = 1
	}

	ctx, ctxCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ctxCancel()

	scopeArray := []string{scope}
	for i := 0; i < maxRetry; i++ {
		logger.Info(fmt.Sprintf("get access token for scope %v, attempt %d/%d", scope, i+1, maxRetry))
		token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: scopeArray})
		if err == nil {
			logger.Info(fmt.Sprintf("fetched the access token. token ExpiresOn: %v", token.ExpiresOn))
			return token.Token, nil
		}
		logger.Error(fmt.Sprintf("failed to get access token for scope %v: %v", scope, err), tag.Error(err))
	}

	logger.Error(fmt.Sprintf("failed to get access token for scope %v after %v attempts", scope, maxRetry))
	return "", fmt.Errorf("failed to get access token for scope %v after %v attempts", scope, maxRetry)
}
