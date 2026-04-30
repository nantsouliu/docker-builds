package session

import (
	"net/url"

	"go.temporal.io/server/azureml/azureauth"
	"go.temporal.io/server/common/config"
)

func getPassword(cfg *config.SQL) string {
	if !cfg.EnableEntraAuth {
		return url.QueryEscape(cfg.Password)
	}

	token, err := azureauth.GetAccessToken(cfg.EntraScope)
	if err != nil {
		return ""
	}
	return token
}
