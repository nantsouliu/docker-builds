package azureauth

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

var (
	credential  azcore.TokenCredential
	initCredErr error
	logger      *slog.Logger
)

func init() {
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: true,
	}))

	credential, initCredErr = azidentity.NewWorkloadIdentityCredential(nil)
	if initCredErr == nil {
		logger.Info("initialized WorkloadIdentityCredential successfully")
	} else {
		logger.Info("falling back to DefaultAzureCredential")
		credential, initCredErr = azidentity.NewDefaultAzureCredential(nil)
		if initCredErr == nil {
			logger.Info("initialized DefaultAzureCredential successfully")
		}
	}

	if initCredErr != nil {
		logger.Error("Failed to initialize Azure credential", "error", initCredErr)
	}
}

func GetAccessToken(scope string) (string, error) {
	if initCredErr != nil {
		logger.Error("azure credential is not initialized", "error", initCredErr)
		return "", initCredErr
	}

	ctx, ctxCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ctxCancel()

	token, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err == nil {
		logger.Info("got the access token successfully", "scope", scope, "expires_on", token.ExpiresOn)
		return token.Token, nil
	}

	logger.Error("failed to get access token", "scope", scope, "error", err)
	return "", err
}
