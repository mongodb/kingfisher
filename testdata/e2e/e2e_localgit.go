package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	regexp "github.com/wasilibs/go-re2"
)

func main() {
	// fmt.Println(">> [*] Testing 'kingfisher local-git' functionality against owasp/wrongsecrets repo.")

	// Remove the existing /tmp/wrongsecrets directory
	if err := os.RemoveAll("/tmp/wrongsecrets"); err != nil {
		fmt.Printf("Error removing /tmp/wrongsecrets: %s\n", err)
		return
	}

	// Clone the owasp/wrongsecrets repository
	gitCloneCmd := exec.Command("git", "clone", "https://github.com/OWASP/wrongsecrets.git", "/tmp/wrongsecrets", "--depth", "1")
	if err := gitCloneCmd.Run(); err != nil {
		fmt.Printf("Error cloning repository: %s\n", err)
		return
	}
	defer os.RemoveAll("/tmp/wrongsecrets")

	// Get the current working directory
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error getting current directory: %s\n", err)
		return
	}

	// Construct the path to main.go
	mainGoPath := filepath.Join(cwd, "main.go")

	// Run the main.go with local-git command
	mainGoCmd := exec.Command("go", "run", mainGoPath, "local-git", "--path", "/tmp/wrongsecrets", "--silent", "--debug", "--confidence", "low")
	outputBytes, err := mainGoCmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running main.go: %s\nOutput: %s\n", err, string(outputBytes))
		return
	}
	output := string(outputBytes)

	// Print output
	// fmt.Println(output)

	// Extract the number of files processed
	re := regexp.MustCompile(`Files Read\.*?: (\d+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) < 2 {
		fmt.Println("Error: Could not find files count")
		os.Exit(1)
		return
	}

	filesCount, err := strconv.Atoi(matches[1])
	if err != nil {
		fmt.Printf("Error parsing files count: %s\n", err)
		os.Exit(1)
		return
	}

	// Check if the files count is greater than 10
	if filesCount <= 10 {
		fmt.Printf("Error: Files count (%d) is not greater than 10\n", filesCount)
		os.Exit(1)
		return
	}

	fmt.Println("Test completed successfully.")
}
