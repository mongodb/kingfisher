package core_test

import (
	"net/http"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/10gen/kingfisher/core"
)

func rootDir() string {
	_, b, _, _ := runtime.Caller(0)
	return filepath.Dir(path.Dir(b))
}

// TestRemoteGit holds the test data for each signature
type TestRemoteGitStruct struct {
	RepoPath            string
	ScmName             string
	ScanRepo            bool
	ScanOrgGroup        bool
	ScanUser            bool
	ExpectedMinFindings int
	ExpectedMinRepos    int
}

func isServiceReachable(url string) bool {
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Head(url)
	if err != nil {
		return false
	}
	return resp.StatusCode == http.StatusOK
}

func NewTestSession(bkfIgnore bool) (*core.Session, error) {
	session := core.PrepareTestSession()
	session.Testing = true
	session.KingfisherIgnore = bkfIgnore
	session.Options.ValidateSecrets = false
	core.GlobalSessionRef = session
	session.InitializeTargetModeClient()
	return session, nil
}

func beginTesting(t *testing.T, testList []TestRemoteGitStruct) {
	githubReachable := isServiceReachable("https://github.com")
	gitlabReachable := isServiceReachable("https://gitlab.com")
	bbReachable := isServiceReachable("https://bitbucket.com")

	for _, test := range testList {
		if strings.EqualFold(test.ScmName, "github") && !githubReachable {
			t.Skip("GitHub is not reachable. Skipping GitHub tests.")
		}
		if strings.EqualFold(test.ScmName, "gitlab") && !gitlabReachable {
			t.Skip("GitLab is not reachable. Skipping GitLab tests.")
		}
		if strings.EqualFold(test.ScmName, "bitbucket") && !bbReachable {
			t.Skip("BitBucket is not reachable. Skipping GitLab tests.")
		}

		sess, err := NewTestSession(false)
		if err != nil {
			t.Fatal(err)
		}

		// sess.Options.Git.CommitDepth = 2
		if strings.EqualFold(test.ScmName, "gitlab") {
			sess.Options.Authentication.GitLab.GitlabAccessToken = "UNAUTHENTICATED"
			sess.Options.Git.RemoteGitRepoPath = test.RepoPath
			sess.ReqScanMode = core.RemoteGitLab
			sess.Options.ScanModeRequested = core.RemoteGitLab
		} else if strings.EqualFold(test.ScmName, "github") {
			sess.Options.Authentication.GitHub.GithubAccessToken = "UNAUTHENTICATED"
			sess.Options.Git.RemoteGitRepoPath = test.RepoPath
			sess.ReqScanMode = core.RemoteGitHub
			sess.Options.ScanModeRequested = core.RemoteGitHub
		} else if strings.EqualFold(test.ScmName, "bitbucket") {
			sess.Options.Authentication.BitBucket.BitbucketAccessToken = "UNAUTHENTICATED"
			sess.Options.Git.RemoteGitRepoPath = test.RepoPath
			sess.ReqScanMode = core.RemoteBitBucket
			sess.Options.ScanModeRequested = core.RemoteBitBucket
		}

		sess.Options.Output.Debug = true
		if test.ScanUser {
			sess.Options.Git.RemoteGitPathUser = true
		} else if test.ScanOrgGroup {
			sess.Options.Git.RemoteGitPathOrg = true
		}

		sess.InitGitApiClient()

		if test.ScanRepo {
			core.PrepareGitScanning()
			core.PrintSessionStats(sess)
			//check findings
			if sess.Stats.Findings < test.ExpectedMinFindings {
				t.Errorf("Expected at least %d VALID findings, got %d for repo: %s", test.ExpectedMinFindings, sess.Stats.Findings, test.RepoPath)
			}
		} else if test.ScanOrgGroup || test.ScanUser {
			//check number of repos. Don't actually scan, just ensure we can retrieve them
			core.GatherRemoteGitRepository(sess)
			repoCount := len(sess.Repositories)

			if repoCount < test.ExpectedMinRepos {
				t.Errorf("Expected at least %d repositories, got %d for target: %s", test.ExpectedMinRepos, sess.Stats.Repositories, test.RepoPath)
			}
		}
	}

}

func TestRemoteGit(t *testing.T) {
	//
	//
	var tests = []TestRemoteGitStruct{
		{"https://gitlab.com/micksmix/SecretsTest.git", "gitlab", true, false, false, 50, 0},                    //LAB
		{"https://github.com/micksmix/SecretsTest.git", "github", true, false, false, 50, 0},                    //HUB
		{"https://hashashash@bitbucket.org/hashashash/secretstest.git", "bitbucket", true, false, false, 50, 0}, //BB
		{"micksmix", "github", false, false, true, 0, 15},                                                       // Test 'user' scan on github
		{"micksmix", "gitlab", false, false, true, 0, 4},                                                        // Test 'user' scan on gitlab
		{"hashashash", "bitbucket", false, false, true, 0, 2},                                                   // Test 'user' scan on bitbucket
		{"mongodb", "github", false, true, false, 0, 100},                                                       // Test 'org/group' lookup on github
		{"libeigen", "gitlab", false, true, false, 0, 5},                                                        // Test 'org/group' lookup on gitlab
		{"thompsonlabs", "bitbucket", false, true, false, 0, 5},                                                 // Test 'org/group' lookup on gitlab
	}

	beginTesting(t, tests)

}
