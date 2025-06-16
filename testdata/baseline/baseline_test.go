package core

import (
	"io/ioutil"
	"os"
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

func NewTestSession(baselineFilename string) (*core.Session, error) {
	session := core.PrepareTestSession()
	session.Testing = true
	session.ReqScanMode = core.LocalFiles
	session.Options.ValidateSecrets = true
	session.Options.BaselineFilename = baselineFilename
	session.Options.KingfisherTempDir = core.GetTempDir()
	core.GlobalSessionRef = session
	session.InitializeTargetModeClient()
	return session, nil
}

func beginTesting(t *testing.T, testfile string, expectedSkippedFindings, expectedFindingsSuppressKingfisher int) {
	rootdir := rootDir()
	testfilePath := filepath.Join(rootdir, testfile)
	_, filename := filepath.Split(testfilePath)

	byteBaseLine := []byte(`FileContent:
    matches: []
FilePaths:
    matches: []
ExactFindings:
    matches:
        - filepath: testdata/ruby_vulnerable.rb
          findinghash: 701c302855ecc97e8415c44f37123bc2ca0c3343bd87028682aaaeaa90568084
          linenum: 40
          lastupdated: Tue Apr 16 13:04:10 PDT 2024
        - filepath: testdata/ruby_vulnerable.rb
          findinghash: 065d1e2faeae9328ca8b2f2754afa6c196d3ef2da2720dabca7e5161d67a6ca1
          linenum: 40
          lastupdated: Tue Apr 16 13:04:10 PDT 2024
`)

	// Write byteBaseline to a file in a temp directory and give yaml extension
	tempFile, err := ioutil.TempFile("", "baseline-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tempFile.Name()) // Clean up the file after test

	if _, err := tempFile.Write(byteBaseLine); err != nil {
		t.Fatal(err)
	}
	if err := tempFile.Close(); err != nil {
		t.Fatal(err)
	}

	sess, err := NewTestSession(tempFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	matchFile := core.NewMatchFile(testfilePath, sess, nil)
	core.BeginFileAnalysis(matchFile)
	if sess.Stats.SkippedFindings != expectedSkippedFindings {
		core.PrintSessionStats(sess)
		t.Errorf("Expected %d findings, got %d -- file: <%s>", expectedSkippedFindings, sess.Stats.SkippedFindings, filename)
	}
}

func TestBaselineFeature(t *testing.T) {

	tests := []struct {
		fileName                           string
		expectedSkippedFindings            int
		expectedFindingsSuppressKingfisher int
	}{
		{"ruby_vulnerable.rb", 3, 0},
	}

	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			beginTesting(t, tt.fileName, tt.expectedSkippedFindings, tt.expectedFindingsSuppressKingfisher)
		})
	}

}
