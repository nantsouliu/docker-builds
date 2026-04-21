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
