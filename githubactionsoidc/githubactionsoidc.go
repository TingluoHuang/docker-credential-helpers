package githubactionsoidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/docker/docker-credential-helpers/credentials"
)

// GitHubActionsOidc handles secrets using the OIDC token from GitHub Actions.
type GitHubActionsOidc struct {
	LogFile *os.File
}

// Add is a no-op for GitHub Actions OIDC helper.
func (gh GitHubActionsOidc) Add(creds *credentials.Credentials) error {
	gh.LogFile.WriteString(fmt.Sprintf("%s: Adding credentials for server: %s\n", time.Now().UTC().Format(time.RFC3339), creds.ServerURL))
	return nil
}

// Delete is a no-op for GitHub Actions OIDC helper.
func (gh GitHubActionsOidc) Delete(serverURL string) error {
	gh.LogFile.WriteString(fmt.Sprintf("%s: Deleting credentials for server: %s\n", time.Now().UTC().Format(time.RFC3339), serverURL))
	return nil
}

// Get retrieves OIDC token from GitHub Actions environment.
func (gh GitHubActionsOidc) Get(serverURL string) (string, string, error) {
	gh.LogFile.WriteString(fmt.Sprintf("%s: Getting OIDC token: %s\n", time.Now().UTC().Format(time.RFC3339), serverURL))

	oidcRequestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	oidcRequestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	if oidcRequestURL == "" || oidcRequestToken == "" {
		gh.LogFile.WriteString(fmt.Sprintf("%s: Missing OIDC request URL or token\n", time.Now().UTC().Format(time.RFC3339)))
		return "", "", credentials.NewErrCredentialsNotFound()
	}

	oidcAudience := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_AUDIENCE")
	if oidcAudience != "" {
		// Check if URL already has query parameters
		separator := "?"
		if strings.Contains(oidcRequestURL, "?") {
			separator = "&"
		}
		oidcRequestURL = oidcRequestURL + separator + "audience=" + url.QueryEscape(oidcAudience)
		gh.LogFile.WriteString(fmt.Sprintf("%s: Added OIDC audience to request URL: %s\n", time.Now().UTC().Format(time.RFC3339), oidcRequestURL))
	}

	// make http get request to oidcRequestUrl with oidcRequestToken as bearer token header
	req, err := http.NewRequest("GET", oidcRequestURL, nil)
	if err != nil {
		gh.LogFile.WriteString(fmt.Sprintf("%s: Failed to create HTTP request: %v\n", time.Now().UTC().Format(time.RFC3339), err))
		return "", "", credentials.NewErrCredentialsNotFound()
	}
	req.Header.Set("Authorization", "Bearer "+oidcRequestToken)
	req.Header.Set("User-Agent", "Docker-Credential-Helper-GitHubActionsOIDC")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		gh.LogFile.WriteString(fmt.Sprintf("%s: Failed to send HTTP request: %v\n", time.Now().UTC().Format(time.RFC3339), err))
		return "", "", credentials.NewErrCredentialsNotFound()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		gh.LogFile.WriteString(fmt.Sprintf("%s: Received non-OK HTTP status: %d\n", time.Now().UTC().Format(time.RFC3339), resp.StatusCode))
		return "", "", credentials.NewErrCredentialsNotFound()
	}

	// read the response as json
	var respBody struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		gh.LogFile.WriteString(fmt.Sprintf("%s: Failed to decode HTTP response: %v\n", time.Now().UTC().Format(time.RFC3339), err))
		return "", "", credentials.NewErrCredentialsNotFound()
	}

	gh.LogFile.WriteString(fmt.Sprintf("%s: Successfully retrieved OIDC token: %s\n", time.Now().UTC().Format(time.RFC3339), respBody.Value))
	return "github_actions", respBody.Value, nil
}

// List returns empty map for GitHub Actions OIDC helper (no stored credentials).
func (gh GitHubActionsOidc) List() (map[string]string, error) {
	gh.LogFile.WriteString(fmt.Sprintf("%s: Listing credentials\n", time.Now().UTC().Format(time.RFC3339)))
	return nil, nil
}
