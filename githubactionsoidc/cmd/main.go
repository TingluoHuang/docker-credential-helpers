package main

import (
	"os"
	"path"

	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/docker/docker-credential-helpers/githubactionsoidc"
)

func main() {
	logFile, err := os.OpenFile(path.Join(os.TempDir(), "github_actions_oidc.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer logFile.Close()

	credentials.Serve(githubactionsoidc.GitHubActionsOidc{LogFile: logFile})
}
