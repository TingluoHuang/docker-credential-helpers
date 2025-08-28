package githubactionsoidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/docker/docker-credential-helpers/credentials"
)

func TestGitHubActionsOidcHelper_Get_WithEnvironmentVariables(t *testing.T) {
	// Set up test environment variables
	originalRequestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	originalRequestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	originalAudience := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_AUDIENCE")

	// Clean up after test
	defer func() {
		if originalRequestURL != "" {
			os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", originalRequestURL)
		} else {
			os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL")
		}
		if originalRequestToken != "" {
			os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", originalRequestToken)
		} else {
			os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		}
		if originalAudience != "" {
			os.Setenv("ACTIONS_ID_TOKEN_REQUEST_AUDIENCE", originalAudience)
		} else {
			os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_AUDIENCE")
		}
	}()

	helper := GitHubActionsOidc{}

	// Test case 1: Missing environment variables should return credentials not found
	t.Run("missing environment variables", func(t *testing.T) {
		os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL")
		os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

		_, _, err := helper.Get("https://registry.example.com")
		if !credentials.IsErrCredentialsNotFound(err) {
			t.Fatalf("expected ErrCredentialsNotFound when environment variables are missing, got %v", err)
		}
	})

	// Test case 2: Missing request URL should return credentials not found
	t.Run("missing request URL", func(t *testing.T) {
		os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL")
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

		_, _, err := helper.Get("https://registry.example.com")
		if !credentials.IsErrCredentialsNotFound(err) {
			t.Fatalf("expected ErrCredentialsNotFound when request URL is missing, got %v", err)
		}
	})

	// Test case 3: Missing request token should return credentials not found
	t.Run("missing request token", func(t *testing.T) {
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token")
		os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

		_, _, err := helper.Get("https://registry.example.com")
		if !credentials.IsErrCredentialsNotFound(err) {
			t.Fatalf("expected ErrCredentialsNotFound when request token is missing, got %v", err)
		}
	})

	// Test case 4: Successful OIDC token retrieval with mock server
	t.Run("successful token retrieval", func(t *testing.T) {
		// Create a mock server that returns a valid OIDC token response
		mockToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.token"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify the request has the correct Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader != "Bearer test-token" {
				http.Error(w, "Invalid authorization", http.StatusUnauthorized)
				return
			}

			// Verify User-Agent header
			userAgent := r.Header.Get("User-Agent")
			if userAgent != "Docker-Credential-Helper-GitHubActionsOIDC" {
				http.Error(w, "Invalid user agent", http.StatusBadRequest)
				return
			}

			// Return mock OIDC token response
			response := map[string]string{"value": mockToken}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		// Set up environment variables to use our mock server
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

		username, secret, err := helper.Get("https://registry.example.com")
		if err != nil {
			t.Fatalf("expected successful token retrieval, got error: %v", err)
		}

		if username != "github_actions" {
			t.Fatalf("expected username 'github_actions', got '%s'", username)
		}

		if secret != mockToken {
			t.Fatalf("expected secret '%s', got '%s'", mockToken, secret)
		}
	})

	// Test case 5: HTTP error response
	t.Run("http error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}))
		defer server.Close()

		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

		_, _, err := helper.Get("https://registry.example.com")
		if !credentials.IsErrCredentialsNotFound(err) {
			t.Fatalf("expected ErrCredentialsNotFound for HTTP error, got %v", err)
		}
	})

	// Test case 6: Invalid JSON response
	t.Run("invalid json response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("invalid json"))
		}))
		defer server.Close()

		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

		_, _, err := helper.Get("https://registry.example.com")
		if !credentials.IsErrCredentialsNotFound(err) {
			t.Fatalf("expected ErrCredentialsNotFound for invalid JSON, got %v", err)
		}
	})

	// Test case 7: OIDC audience parameter
	t.Run("with audience parameter", func(t *testing.T) {
		// Clean up any existing audience environment variable first
		os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_AUDIENCE")

		mockToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.audience.token"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify that audience parameter is included in the URL
			audience := r.URL.Query().Get("audience")
			if audience != "https://registry.example.com" {
				http.Error(w, "Missing or invalid audience", http.StatusBadRequest)
				return
			}

			response := map[string]string{"value": mockToken}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL)
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")
		os.Setenv("ACTIONS_ID_TOKEN_REQUEST_AUDIENCE", "https://registry.example.com")

		username, secret, err := helper.Get("https://registry.example.com")
		if err != nil {
			t.Fatalf("expected successful token retrieval with audience, got error: %v", err)
		}

		if username != "github_actions" {
			t.Fatalf("expected username 'github_actions', got '%s'", username)
		}

		if secret != mockToken {
			t.Fatalf("expected secret '%s', got '%s'", mockToken, secret)
		}
	})
}

func TestGitHubActionsOidcHelper_Add(t *testing.T) {
	helper := GitHubActionsOidc{}
	creds := &credentials.Credentials{
		ServerURL: "https://registry.example.com",
		Username:  "testuser",
		Secret:    "testpassword",
	}

	// Add should be a no-op and return nil
	err := helper.Add(creds)
	if err != nil {
		t.Fatalf("expected Add to return nil (no-op), got %v", err)
	}
}

func TestGitHubActionsOidcHelper_Delete(t *testing.T) {
	helper := GitHubActionsOidc{}

	// Delete should be a no-op and return nil
	err := helper.Delete("https://registry.example.com")
	if err != nil {
		t.Fatalf("expected Delete to return nil (no-op), got %v", err)
	}
}

func TestGitHubActionsOidcHelper_List(t *testing.T) {
	helper := GitHubActionsOidc{}

	// List should return nil (no stored credentials)
	auths, err := helper.List()
	if err != nil {
		t.Fatalf("expected List to return nil error, got %v", err)
	}
	if auths != nil {
		t.Fatalf("expected List to return nil map, got %v", auths)
	}
}
