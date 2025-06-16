package core_test

import (
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/10gen/kingfisher/core"
)

func rootDir() string {
	_, b, _, _ := runtime.Caller(0)
	return filepath.Dir(path.Dir(b))
}

func NewTestSession(bkfIgnore bool) (*core.Session, error) {
	session := core.PrepareTestSession()
	session.Testing = true
	session.ReqScanMode = core.LocalFiles
	session.KingfisherIgnore = bkfIgnore
	core.GlobalSessionRef = session
	session.InitializeTargetModeClient()
	return session, nil
}

func beginTesting(t *testing.T, testfile string, expectedFindings, expectedFindingsSuppressKingfisher int) {
	rootdir := rootDir()
	testfilePath := filepath.Join(rootdir, testfile)
	_, filename := filepath.Split(testfilePath)

	sess, err := NewTestSession(false)
	if err != nil {
		t.Fatal(err)
	}

	matchFile := core.NewMatchFile(testfilePath, sess, nil)
	core.BeginFileAnalysis(matchFile)
	if sess.Stats.Findings < expectedFindings {
		core.PrintSessionStats(sess)
		t.Errorf("Expected %d findings, got %d -- file: <%s>", expectedFindings, sess.Stats.Findings, filename)
	}

}

func TestParseFiles(t *testing.T) {
	tests := []struct {
		fileName                           string
		expectedFindings                   int
		expectedFindingsSuppressKingfisher int
	}{
		{"c_vulnerable.c", 4, 0},
		{"cpp_vulnerable.cpp", 3, 0},
		{"csharp_vulnerable.cs", 5, 0},
		{"elixir_vulnerable.exs", 5, 0},
		{"generic_secrets.py", 15, 0},
		{"go_vulnerable.go", 10, 0},
		{"kotlin_vulnerable.kt", 10, 0},
		{"java_vulnerable.java", 15, 0},
		{"javascript_vulnerable.js", 7, 0},
		{"json_vulnerable.json", 2, 0},
		{"objc_vulnerable.m", 5, 0},
		{"php_vulnerable.php", 6, 0},
		{"python2_vulnerable.py", 11, 0},
		{"python_vulnerable.py", 16, 0},
		{"ruby_vulnerable.rb", 6, 0},
		{"rust_vulnerable.rs", 1, 0},
		{"scala_vulnerable.scala", 5, 0},
		{"shell_vulnerable.sh", 9, 0},
		{"swift_vulnerable.swift", 10, 0},
		{"tsx_vulnerable.tsx", 6, 0},
		{"typescript_vulnerable.ts", 8, 0},
		{"yaml_vulnerable.yaml", 5, 0},
	}

	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			beginTesting(t, tt.fileName, tt.expectedFindings, tt.expectedFindingsSuppressKingfisher)
		})
	}
}
