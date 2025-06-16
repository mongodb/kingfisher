// main.go
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"text/tabwriter"
	"time"
)

var (
	// Global counter for intercepted HTTP requests.
	netReqCount int64
	// BASE_DIR will be set from a flag or default to os.TempDir()/benchmark.
	BASE_DIR string
)

// Repo list: name and git URL.
var repos = []struct {
	name string
	url  string
}{
	{"croc", "https://github.com/schollz/croc.git"},
	{"rails", "https://github.com/rails/rails.git"},
	{"ruby", "https://github.com/ruby/ruby.git"},
	{"gitlab", "https://gitlab.com/gitlab-org/gitlab.git"},
	{"django", "https://github.com/django/django.git"},
	{"lucene", "https://github.com/apache/lucene.git"},
	{"mongodb", "https://github.com/mongodb/mongo.git"},
	{"linux", "https://github.com/torvalds/linux.git"},
	{"typescript", "https://github.com/microsoft/TypeScript.git"},
}

// RepoResult holds timing, tool outputs, and network request counts.
type RepoResult struct {
	Repo string
	// Runtimes in seconds.
	KFTime      time.Duration
	KFFindings  int
	KFValidated int
	KFNetReq    int64
	THTime      time.Duration
	THFindings  int
	THVerified  int
	THNetReq    int64
	GLTime      time.Duration
	GLFindings  int
	GLNetReq    int64
	DSTime      time.Duration
	DSFindings  int
	DSNetReq    int64
}

// --- Proxy Implementation ---

// proxyHandler counts each request then forwards it.
type proxyHandler struct{}

func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	atomic.AddInt64(&netReqCount, 1)
	if req.Method == "CONNECT" {
		handleTunneling(w, req)
	} else {
		handleHTTP(w, req)
	}
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	proxy := httputil.ReverseProxy{
		Director: func(r *http.Request) {},
	}
	proxy.ServeHTTP(w, req)
}

func handleTunneling(w http.ResponseWriter, req *http.Request) {
	destConn, err := net.Dial("tcp", req.Host)
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}
	hijacker, ok := w.(interface {
		Hijack() (net.Conn, *bufio.ReadWriter, error)
	})
	if !ok {
		http.Error(w, "Hijacking not supported", 500)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		clientConn.Close()
		destConn.Close()
		return
	}
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func runProxy() {
	server := &http.Server{
		Addr:    "127.0.0.1:9191",
		Handler: &proxyHandler{},
	}
	log.Printf("Starting proxy on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Proxy error: %v", err)
	}
}

// --- Helper Functions ---

func getSystemInfo() string {
	osInfo := runtime.GOOS
	arch := runtime.GOARCH
	cpuCount := runtime.NumCPU()
	memInfo := "N/A"
	if osInfo == "darwin" {
		out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
		if err == nil {
			if memBytes, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); err == nil {
				memInfo = fmt.Sprintf("%.2f GB", float64(memBytes)/(1024*1024*1024))
			}
		}
	} else if osInfo == "linux" {
		data, err := ioutil.ReadFile("/proc/meminfo")
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(data))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "MemTotal:") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						if memKb, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
							memInfo = fmt.Sprintf("%.2f GB", float64(memKb)/(1024*1024))
						}
					}
					break
				}
			}
		}
	}
	return fmt.Sprintf("OS: %s\nArchitecture: %s\nCPU Cores: %d\nRAM: %s\n", osInfo, arch, cpuCount, memInfo)
}

func cloneRepo(repoName, repoURL string) error {
	dest := filepath.Join(BASE_DIR, repoName)
	if _, err := os.Stat(dest); os.IsNotExist(err) {
		fmt.Printf("Cloning %s...\n", repoName)
		cmd := exec.Command("git", "clone", repoURL, dest)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	fmt.Printf("Repo '%s' exists, skipping clone.\n", repoName)
	return nil
}

func runCommand(cmdArgs []string, cwd string, ignoreErrors bool, combineStderr bool) (time.Duration, int, string, error) {
	atomic.StoreInt64(&netReqCount, 0)
	start := time.Now()
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "HTTP_PROXY=127.0.0.1:9191", "HTTPS_PROXY=127.0.0.1:9191")
	var output []byte
	var err error
	if combineStderr {
		output, err = cmd.CombinedOutput()
	} else {
		output, err = cmd.Output()
	}
	elapsed := time.Since(start)
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			if !ignoreErrors {
				return elapsed, exitCode, "", err
			}
		}
	}
	fmt.Fprintf(os.Stderr, "[TIME] Command: %s took %.2fs\n", strings.Join(cmdArgs, " "), elapsed.Seconds())
	return elapsed, exitCode, string(output), nil
}

func parseKingfisherOutput(output string) (int, int) {
	total, validated := 0, 0
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		var data map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &data); err == nil {
			if v, ok := data["findings"].(float64); ok {
				total = int(v)
			}
			if v, ok := data["successful_validations"].(float64); ok {
				validated = int(v)
			}
		}
	}
	return total, validated
}

func parseTrufflehogOutput(output string) (int, int) {
	total, verified := 0, 0
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		var data map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &data); err == nil {
			if u, ok := data["unverified_secrets"].(float64); ok {
				total += int(u)
			}
			if v, ok := data["verified_secrets"].(float64); ok {
				verified = int(v)
				total += int(v)
			}
		}
	}
	return total, verified
}

func parseGitleaksOutput(reportPath string) int {
	data, err := ioutil.ReadFile(reportPath)
	if err != nil {
		return 0
	}
	var arr []interface{}
	if err := json.Unmarshal(data, &arr); err == nil {
		return len(arr)
	}
	return 0
}

func parseDetectSecretsOutput(output string) int {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(output), &data); err != nil {
		return 0
	}
	results := data["results"]
	sum := 0
	if m, ok := results.(map[string]interface{}); ok {
		for _, v := range m {
			if arr, ok := v.([]interface{}); ok {
				sum += len(arr)
			}
		}
	}
	return sum
}

func formatDuration(d time.Duration) string {
	secs := int(d.Seconds() + 0.5)
	m := secs / 60
	s := secs % 60
	if m > 0 {
		return fmt.Sprintf("%.2f (%dm %ds)", d.Seconds(), m, s)
	}
	return fmt.Sprintf("%.2f (%ds)", d.Seconds(), s)
}

// --- Output Functions for Markdown Tables ---

func printRuntimeTable(results []RepoResult) {
	fmt.Println("### Runtime Comparison (seconds)")
	fmt.Println()
	fmt.Println("| Repository | Kingfisher Runtime | TruffleHog Runtime | GitLeaks Runtime | detect-secrets Runtime |")
	fmt.Println("|------------|--------------------|--------------------|------------------|------------------------|")
	for _, r := range results {
		fmt.Printf("| %s | %.2f | %.2f | %.2f | %.2f |\n",
			r.Repo,
			r.KFTime.Seconds(),
			r.THTime.Seconds(),
			r.GLTime.Seconds(),
			r.DSTime.Seconds())
	}
	fmt.Println()
}

func printFindingsTable(results []RepoResult) {
	fmt.Println("### Validated/Verified Findings Comparison")
	fmt.Println()
	fmt.Println("Note: For GitLeaks and detect-secrets, validated/verified counts are not available.")
	fmt.Println()
	fmt.Println("| Repository | Kingfisher Validated | TruffleHog Verified | GitLeaks Verified | detect-secrets Verified |")
	fmt.Println("|------------|----------------------|---------------------|-------------------|-------------------------|")
	for _, r := range results {
		fmt.Printf("| %s | %d | %d | %d | %d |\n",
			r.Repo,
			r.KFValidated,
			r.THVerified,
			0,
			0)
	}
	fmt.Println()
}

func printNetworkTable(results []RepoResult) {
	fmt.Println("### Network Requests Comparison")
	fmt.Println()
	fmt.Println("| Repository | Kingfisher Network Requests | TruffleHog Network Requests | GitLeaks Network Requests | detect-secrets Network Requests |")
	fmt.Println("|------------|-----------------------------|-----------------------------|---------------------------|----------------------------------|")
	for _, r := range results {
		fmt.Printf("| %s | %d | %d | %d | %d |\n",
			r.Repo,
			r.KFNetReq,
			r.THNetReq,
			r.GLNetReq,
			r.DSNetReq)
	}
	fmt.Println()
}

// --- QuickChart.io Integration ---
// This function builds chart URLs using QuickChart.io and prints Markdown image links.
func printQuickChartLinks(results []RepoResult) {
	labels := []string{}
	for _, r := range results {
		labels = append(labels, r.Repo)
	}

	chartURL := func(title string, datasetMap map[string][]float64) string {
		type dataset struct {
			Label string    `json:"label"`
			Data  []float64 `json:"data"`
		}
		data := struct {
			Type string `json:"type"`
			Data struct {
				Labels   []string  `json:"labels"`
				Datasets []dataset `json:"datasets"`
			} `json:"data"`
			Options map[string]interface{} `json:"options"`
		}{
			Type: "bar",
		}
		data.Data.Labels = labels
		for label, vals := range datasetMap {
			data.Data.Datasets = append(data.Data.Datasets, dataset{Label: label, Data: vals})
		}
		data.Options = map[string]interface{}{
			"title": map[string]string{"display": "true", "text": title},
			"scales": map[string]interface{}{
				"yAxes": []map[string]interface{}{
					{"ticks": map[string]interface{}{"beginAtZero": true}},
				},
			},
		}
		jsonBytes, err := json.Marshal(data)
		if err != nil {
			log.Printf("Error marshaling JSON: %v", err)
		}
		// URL-encode the JSON configuration.
		return "https://quickchart.io/chart?c=" + url.QueryEscape(string(jsonBytes))
	}

	// Build datasets.
	var (
		kfTimes, thTimes, glTimes, dsTimes []float64
		kfValids, thVerifs, glZero, dsZero []float64
		kfReqs, thReqs, glReqs, dsReqs     []float64
	)
	for _, r := range results {
		kfTimes = append(kfTimes, r.KFTime.Seconds())
		thTimes = append(thTimes, r.THTime.Seconds())
		glTimes = append(glTimes, r.GLTime.Seconds())
		dsTimes = append(dsTimes, r.DSTime.Seconds())

		kfValids = append(kfValids, float64(r.KFValidated))
		thVerifs = append(thVerifs, float64(r.THVerified))
		glZero = append(glZero, 0)
		dsZero = append(dsZero, 0)

		kfReqs = append(kfReqs, float64(r.KFNetReq))
		thReqs = append(thReqs, float64(r.THNetReq))
		glReqs = append(glReqs, float64(r.GLNetReq))
		dsReqs = append(dsReqs, float64(r.DSNetReq))
	}

	fmt.Println("### QuickChart.io Visualizations")
	fmt.Println()
	fmt.Println("#### Runtime Chart")
	fmt.Println("![Runtime Comparison](" + chartURL("Runtime Comparison (seconds)", map[string][]float64{
		"Kingfisher":     kfTimes,
		"TruffleHog":     thTimes,
		"GitLeaks":       glTimes,
		"detect-secrets": dsTimes,
	}) + ")")
	fmt.Println()
	fmt.Println("#### Validated/Verified Findings Chart")
	fmt.Println("![Findings Comparison](" + chartURL("Validated/Verified Findings", map[string][]float64{
		"Kingfisher":     kfValids,
		"TruffleHog":     thVerifs,
		"GitLeaks":       glZero,
		"detect-secrets": dsZero,
	}) + ")")
	fmt.Println()
	fmt.Println("#### Network Requests Chart")
	fmt.Println("![Network Requests](" + chartURL("Network Requests Made", map[string][]float64{
		"Kingfisher":     kfReqs,
		"TruffleHog":     thReqs,
		"GitLeaks":       glReqs,
		"detect-secrets": dsReqs,
	}) + ")")
	fmt.Println()
}

func main() {
	// Parse command-line flags.
	baseDirFlag := flag.String("basedir", "", "Directory to clone repos (default: os.TempDir()/benchmark)")
	markdownFlag := flag.Bool("markdown", true, "Output in Markdown format")
	flag.Parse()

	// Set BASE_DIR.
	if *baseDirFlag == "" {
		BASE_DIR = filepath.Join(os.TempDir(), "benchmark")
	} else {
		BASE_DIR = *baseDirFlag
	}
	// Ensure BASE_DIR exists.
	os.MkdirAll(BASE_DIR, 0755)

	// Start the proxy in a goroutine.
	go runProxy()
	time.Sleep(500 * time.Millisecond)

	fmt.Println(getSystemInfo())

	var results []RepoResult

	// Process each repository.
	for _, r := range repos {
		if err := cloneRepo(r.name, r.url); err != nil {
			log.Fatalf("Error cloning %s: %v", r.name, err)
		}
		repoPath := filepath.Join(BASE_DIR, r.name)
		var res RepoResult
		res.Repo = r.name

		// Kingfisher.
		fmt.Printf("[Kingfisher] Scanning %s...\n", repoPath)
		kfArgs := []string{"kingfisher", "scan", repoPath, "--no-dedup", "--format", "json"}
		kfTime, _, kfOut, err := runCommand(kfArgs, ".", false, false)
		if err != nil {
			log.Printf("Error running kingfisher: %v", err)
		}
		res.KFTime = kfTime
		res.KFFindings, res.KFValidated = parseKingfisherOutput(kfOut)
		res.KFNetReq = atomic.LoadInt64(&netReqCount)

		// TruffleHog.
		fmt.Printf("\n[TruffleHog] Scanning %s...\n", repoPath)
		fileURI := "file://" + repoPath
		thArgs := []string{"trufflehog", "git", fileURI, "--json"}
		thTime, _, thOut, err := runCommand(thArgs, ".", false, true)
		if err != nil {
			log.Printf("Error running trufflehog: %v", err)
		}
		res.THTime = thTime
		res.THFindings, res.THVerified = parseTrufflehogOutput(thOut)
		res.THNetReq = atomic.LoadInt64(&netReqCount)

		// GitLeaks.
		fmt.Printf("\n[GitLeaks] Scanning %s...\n", repoPath)
		glReport := filepath.Join(BASE_DIR, fmt.Sprintf("gl-%s.json", r.name))
		glArgs := []string{"gitleaks", "git", "-v", repoPath, "--report-path", glReport}
		glTime, _, _, _ := runCommand(glArgs, ".", true, false)
		res.GLTime = glTime
		res.GLFindings = parseGitleaksOutput(glReport)
		res.GLNetReq = atomic.LoadInt64(&netReqCount)

		// detect-secrets.
		fmt.Printf("\n[detect-secrets] Scanning %s...\n", repoPath)
		dsArgs := []string{"detect-secrets", "scan", repoPath}
		dsTime, _, dsOut, err := runCommand(dsArgs, ".", false, false)
		if err != nil {
			log.Printf("Error running detect-secrets: %v", err)
		}
		res.DSTime = dsTime
		res.DSFindings = parseDetectSecretsOutput(dsOut)
		res.DSNetReq = atomic.LoadInt64(&netReqCount)

		results = append(results, res)
	}

	// --- Output Report in Markdown ---
	if *markdownFlag {
		// Print separate summary tables.
		printRuntimeTable(results)
		printFindingsTable(results)
		printNetworkTable(results)
		// Print QuickChart.io image links.
		printQuickChartLinks(results)
	} else {
		// Fallback to a text table.
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "Repository\tKingfisher Runtime\tKingfisher Findings\tKingfisher Validated\tKingfisher Network Requests\tTruffleHog Runtime\tTruffleHog Findings\tTruffleHog Verified\tTruffleHog Network Requests\tGitLeaks Runtime\tGitLeaks Findings\tGitLeaks Network Requests\tdetect-secrets Runtime\tdetect-secrets Findings\tdetect-secrets Network Requests")
		fmt.Fprintln(w, "----------\t------------------\t---------------------\t----------------------\t-------------------------\t------------------\t---------------------\t---------------------\t--------------------------\t----------------\t-------------------\t---------------------------\t---------------------\t-------------------------\t--------------------------")
		for _, r := range results {
			fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%s\t%d\t%d\t%d\t%s\t%d\t%d\t%s\t%d\t%d\n",
				r.Repo,
				formatDuration(r.KFTime), r.KFFindings, r.KFValidated, r.KFNetReq,
				formatDuration(r.THTime), r.THFindings, r.THVerified, r.THNetReq,
				formatDuration(r.GLTime), r.GLFindings, r.GLNetReq,
				formatDuration(r.DSTime), r.DSFindings, r.DSNetReq)
		}
		w.Flush()
	}
	fmt.Println("\n*Lower runtimes are better. Validated/Verified counts are reported where available. 'Network Requests' indicates the number of HTTP requests made during scanning.*")
	fmt.Println(getSystemInfo())
}
