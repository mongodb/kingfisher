package core_test

import (
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/10gen/kingfisher/core"
)

func rootDir() string {
	_, b, _, _ := runtime.Caller(0)
	return filepath.Dir(path.Dir(b))
}

// TestSignatureData holds the test data for each signature
type TestSignatureData struct {
	SignatureID     string
	ExpectedValid   int
	ExpectedInvalid int
}

func NewTestSession(bkfIgnore bool) (*core.Session, error) {
	session := core.PrepareTestSession()
	session.Testing = true
	session.ReqScanMode = core.LocalFiles
	session.KingfisherIgnore = bkfIgnore
	session.Options.ValidateSecrets = true
	core.GlobalSessionRef = session
	session.InitializeTargetModeClient()
	return session, nil
}

func beginTesting(t *testing.T, fileWithSecrets string, testList []TestSignatureData) {
	testfilePath := fileWithSecrets
	//_, filename := filepath.Split(testfilePath)

	sess, err := NewTestSession(false)
	if err != nil {
		t.Fatal(err)
	}
	matchFile := core.NewMatchFile(testfilePath, sess, nil)
	findingsList := core.BeginFileAnalysis(matchFile)

	// scanning of file is now done

	for _, test := range testList {

		foundValid := 0
		foundInvalid := 0

		sigDescription := ""
		for _, v := range findingsList {
			if v.Signatureid == test.SignatureID {
				if strings.EqualFold(v.Validated, core.ValidationSuccess) {
					foundValid += 1
				} else if strings.EqualFold(v.Validated, core.ValidationFailure) {
					foundInvalid += 1
				}
				sigDescription = v.Description
			}
		}
		if foundValid != test.ExpectedValid {
			core.PrintSessionStats(sess)
			t.Errorf("Expected %d VALID findings, got %d -- <%s> %s", test.ExpectedValid, foundValid, sigDescription, test.SignatureID)
		}

		if foundInvalid != test.ExpectedInvalid {
			core.PrintSessionStats(sess)
			t.Errorf("Expected %d invalid findings, got %d -- <%s> %s", test.ExpectedInvalid, foundInvalid, sigDescription, test.SignatureID)
		}
	}

}

func TestParseFiles(t *testing.T) {
	//
	parentDir := filepath.Dir(filepath.Join(".", "..", "..", "..", ".."))
	relPath := filepath.Join(parentDir, "test-secrets.txt")
	absPath, err := filepath.Abs(relPath)
	if err != nil {
		t.Fatalf("Error getting absolute path: %v", err)
	}
	fileWithSecrets := absPath

	//
	//
	var tests = []TestSignatureData{
		{"8e1ab338-e7b6-4940-835d-77dd4886d1bd", 1, 1}, // AWS Secret Access Key
		{"c8ceb744-6250-4bec-b1cc-a4578d439c32", 1, 0}, // Beamer API Key
		// {"f48a3fed-cddd-4be2-96aa-7aa1b79f5f7d", 2, 0}, // Box.com API Key
		{"080d463d-623c-4601-8f02-a872e2d2e1be", 0, 1}, // Dropbox API secret/key
		{"90039304-f743-4b5f-960f-4e8e73595e31", 1, 0}, // MongoDB API PUBLIC Key
		{"41342148-7420-4af4-ab9c-43ccf2a0a96a", 1, 0}, // MongoDB API Private Key
		{"eebe43c8-59b6-42b2-b781-7681172f8168", 1, 1}, // MongoDB Atlas URI
		{"37c5edde-8b26-454e-814e-c1df70d0c727", 2, 0}, // npm access token
		{"97581c04-0816-4a48-b752-50ac76fe2ba3", 1, 0}, // GCP API Token
		{"0f263ff2-4a4f-465c-90be-0143ea35b742", 1, 0}, // Stripe Key
		{"5b61d5bf-8683-4c1b-97c0-5bb366b3a70b", 1, 0}, // Slack App Token
		{"aca0a44d-d464-437b-bec5-ea2c2ee2518a", 2, 0}, // Slack Webhook
		{"299faa6c-a5b8-4ccc-92ba-c675518d4cf6", 2, 1}, // GitHub Token
		{"0ddf3f0a-41cd-43a2-9aca-5d095e71c483", 2, 1}, // GitLab Private Token
		{"c880513b-304e-46d8-a6da-2b727ddd5687", 1, 1}, // Twilio API ID + Key
	}

	beginTesting(t, fileWithSecrets, tests)

}
