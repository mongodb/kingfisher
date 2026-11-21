// main.go
//
// Benchmark runner: clones a set of repositories, scans each with Kingfisher,
// TruffleHog, and (optionally) GitLeaks through a request-counting proxy, then
// writes a Markdown report and a runtime-comparison PNG.
//
// Every run creates a timestamped results directory (benchmark-<timestamp>/)
// containing each tool's raw output, the comparison_<timestamp>.md report, and
// the runtime-comparison-<timestamp>.png chart.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Types & configuration
// ---------------------------------------------------------------------------

// repo identifies a repository to clone and scan.
type repo struct {
	name string
	url  string
}

// repos is the list of repositories the benchmark clones and scans.
var repos = []repo{
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

// Tool names, used as map keys and column headers throughout the report.
const (
	toolKingfisher = "Kingfisher"
	toolTruffleHog = "TruffleHog"
	toolGitLeaks   = "GitLeaks"
	trialCount     = 5
)

// ScanResult holds the metrics captured for a single tool scanning a single repo.
type ScanResult struct {
	Duration  time.Duration
	Findings  int   // total findings reported
	Validated int   // validated/verified findings (0 when the tool can't validate)
	NetReq    int64 // Plain HTTP requests and HTTPS CONNECT tunnels observed by the proxy
	Error     string
}

// RepoResult aggregates every tool's ScanResult for one repository.
type RepoResult struct {
	Repo     string
	Scans    map[string]ScanResult
	Metadata map[string]string
}

// ---------------------------------------------------------------------------
// Entry point & orchestration
// ---------------------------------------------------------------------------

func main() {
	baseDir := flag.String("basedir", "", "directory to clone repos into (default: $TMPDIR/benchmark)")
	withGitleaks := flag.Bool("gitleaks", true, "include GitLeaks in the benchmark (requires gitleaks in PATH)")
	validate := flag.Bool("validate", false, "enable credential validation (requires -gitleaks=false; no runtime chart)")
	trufflehogInPlace := flag.Bool("trufflehog-in-place", false, "have TruffleHog scan the local repository directly (requires trusted local Git configuration)")
	repoNames := flag.String("repos", "", "comma-separated repository names to scan (default: all)")
	makeChart := flag.Bool("chart", true, "render a runtime-comparison PNG chart")
	outRoot := flag.String("out", ".", "directory under which the timestamped results folder is created")
	chartFrom := flag.String("chart-from", "", "regenerate only the chart from an existing benchmark-<timestamp> directory, then exit")
	withNoseyParkerChart := flag.Bool("nosey-parker-chart", false, "chart Kingfisher vs. NoseyParker from the saved report (requires -chart-from)")
	flag.Parse()

	// Chart-only mode: rebuild the PNG from a previous run's report and exit
	// without cloning or scanning anything.
	if *chartFrom != "" {
		if err := regenerateChart(*chartFrom, *withNoseyParkerChart); err != nil {
			log.Fatalf("regenerating chart: %v", err)
		}
		return
	}
	if *withNoseyParkerChart {
		log.Fatal("-nosey-parker-chart requires -chart-from")
	}
	if *validate && *withGitleaks {
		log.Fatal("-validate requires -gitleaks=false; validation-enabled runs permit only Kingfisher and TruffleHog")
	}
	selected := repos
	if *repoNames != "" {
		selected = nil
		for _, name := range strings.Split(*repoNames, ",") {
			found := false
			for _, r := range repos {
				if r.name == strings.TrimSpace(name) {
					selected = append(selected, r)
					found = true
					break
				}
			}
			if !found {
				log.Fatalf("unknown repository %q", name)
			}
		}
	}
	tools := enabledTools(*withGitleaks)
	for _, tool := range tools {
		if _, err := exec.LookPath(toolBinary(tool)); err != nil {
			log.Fatalf("%s must be installed and on PATH: %v", tool, err)
		}
	}

	cloneDir := *baseDir
	if cloneDir == "" {
		cloneDir = filepath.Join(os.TempDir(), "benchmark")
	}
	cloneDir, err := filepath.Abs(cloneDir)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(cloneDir, 0755); err != nil {
		log.Fatalf("creating clone dir: %v", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	outDir := filepath.Join(*outRoot, "benchmark-"+timestamp)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("creating results dir: %v", err)
	}

	commandFile, err := os.Create(filepath.Join(outDir, "commands.jsonl"))
	if err != nil {
		log.Fatalf("creating command log: %v", err)
	}
	defer commandFile.Close()
	commandLog = commandFile
	versions := collectVersions(tools)

	go runProxy()
	time.Sleep(500 * time.Millisecond)

	fmt.Println(getSystemInfo())

	// Phase 1: clone everything up front. A repo that fails to clone (e.g. a
	// transient remote error) is skipped with a warning rather than aborting the
	// run, so the scans we can do still complete.
	fmt.Println("=== Cloning repositories ===")
	ready := make([]repo, 0, len(selected))
	for _, r := range selected {
		if err := cloneRepo(r, cloneDir); err != nil {
			log.Printf("skipping %s: clone failed: %v", r.name, err)
			continue
		}
		ready = append(ready, r)
	}
	if len(ready) == 0 {
		log.Fatal("no repositories available to scan")
	}

	// Phase 2: scan every successfully-cloned repo with all enabled tools.
	fmt.Println("\n=== Scanning ===")
	results := make([]RepoResult, 0, len(ready))
	for _, r := range ready {
		results = append(results, scanRepo(r, cloneDir, outDir, tools, *validate, *trufflehogInPlace))
		// Keep a report on disk even if a later scan is interrupted.
		var report bytes.Buffer
		writeReport(&report, results, tools, versions, "", timestamp, *validate, *trufflehogInPlace)
		if err := os.WriteFile(filepath.Join(outDir, "comparison_"+timestamp+".md"), report.Bytes(), 0644); err != nil {
			log.Fatalf("saving progress: %v", err)
		}
	}

	// Render the chart (into the results dir) before writing the report, so the
	// report can link to it.
	chartFile := ""
	if *makeChart && !*validate {
		name := "runtime-comparison-" + timestamp + ".png"
		subtitle := runtimeChartSubtitle(monthFromTimestamp(timestamp), trialCount)
		config := buildRuntimeChartConfig(results, tools, versions, subtitle)
		if err := renderChartPNG(config, filepath.Join(outDir, name)); err != nil {
			log.Printf("chart generation failed: %v", err)
		} else {
			chartFile = name
		}
	}

	// Write the Markdown report to both stdout and comparison_<timestamp>.md.
	mdPath := filepath.Join(outDir, "comparison_"+timestamp+".md")
	mdFile, err := os.Create(mdPath)
	if err != nil {
		log.Fatalf("creating report: %v", err)
	}
	writeReport(io.MultiWriter(os.Stdout, mdFile), results, tools, versions, chartFile, timestamp, *validate, *trufflehogInPlace)
	mdFile.Close()

	fmt.Printf("\nResults written to %s/\n", outDir)
}

// enabledTools returns the ordered list of tools to run.
func enabledTools(withGitleaks bool) []string {
	tools := []string{toolKingfisher, toolTruffleHog}
	if withGitleaks {
		tools = append(tools, toolGitLeaks)
	}
	return tools
}

func toolBinary(tool string) string {
	return strings.ToLower(tool)
}

// scanRepo runs sequential trials and rotates which scanner goes first.
func scanRepo(r repo, cloneDir, outDir string, tools []string, validate, trufflehogInPlace bool) RepoResult {
	repoPath := filepath.Join(cloneDir, r.name)
	res := RepoResult{Repo: r.name, Scans: make(map[string]ScanResult, len(tools)), Metadata: repositoryMetadata(repoPath)}
	trials := make(map[string][]ScanResult, len(tools))
	for trial := 0; trial < trialCount; trial++ {
		for i := range tools {
			tool := tools[(i+trial)%len(tools)]
			fmt.Printf("[%s] scanning %s (trial %d/%d)...\n", tool, repoPath, trial+1, trialCount)
			rawPath := filepath.Join(outDir, trialFilename(r.name, tool, trial+1))
			var scan ScanResult
			switch tool {
			case toolKingfisher:
				scan = scanKingfisher(repoPath, rawPath, validate)
			case toolTruffleHog:
				scan = scanTruffleHog(repoPath, rawPath, validate, trufflehogInPlace)
			case toolGitLeaks:
				scan = scanGitleaks(repoPath, rawPath)
			}
			trials[tool] = append(trials[tool], scan)
			if scan.Error != "" {
				log.Printf("%s / %s trial %d failed: %s", r.name, tool, trial+1, scan.Error)
			}
		}
	}
	for _, tool := range tools {
		res.Scans[tool] = medianScan(trials[tool])
	}
	return res
}

func trialFilename(repo, tool string, trial int) string {
	return fmt.Sprintf("%s-%s-trial-%d.json", repo, toolBinary(tool), trial)
}

func medianScan(trials []ScanResult) ScanResult {
	if len(trials) != trialCount {
		return ScanResult{Error: fmt.Sprintf("received %d of %d trials", len(trials), trialCount)}
	}
	var durations [trialCount]time.Duration
	var findings, validated [trialCount]int
	var requests [trialCount]int64
	var failures []string
	for i, scan := range trials {
		if scan.Error != "" {
			failures = append(failures, fmt.Sprintf("trial %d: %s", i+1, scan.Error))
		}
		durations[i] = scan.Duration
		findings[i] = scan.Findings
		validated[i] = scan.Validated
		requests[i] = scan.NetReq
	}
	if len(failures) != 0 {
		return ScanResult{Error: strings.Join(failures, ", ")}
	}
	slices.Sort(durations[:])
	slices.Sort(findings[:])
	slices.Sort(validated[:])
	slices.Sort(requests[:])
	middle := trialCount / 2
	return ScanResult{Duration: durations[middle], Findings: findings[middle], Validated: validated[middle], NetReq: requests[middle]}
}

// repositoryMetadata snapshots the input before scanning; unknown fields retain
// their Git error instead of implying a clean, complete repository.
func repositoryMetadata(path string) map[string]string {
	metadata := map[string]string{"path": path}
	git := func(key string, digest bool, args ...string) {
		out, err := exec.Command("git", append([]string{"-C", path}, args...)...).Output()
		if err != nil {
			metadata[key] = "unknown: " + err.Error()
		} else if digest {
			metadata[key] = fmt.Sprintf("%x", sha256.Sum256(out))
		} else {
			metadata[key] = strings.TrimRight(string(out), "\r\n")
		}
	}
	git("origin", false, "remote", "get-url", "origin")
	git("HEAD", false, "rev-parse", "HEAD")
	git("shallow", false, "rev-parse", "--is-shallow-repository")
	git("worktree_status", false, "status", "--porcelain=v1", "--untracked-files=all")
	git("refs_sha256", true, "for-each-ref", "--sort=refname", "--format=%(refname) %(objectname)")
	return metadata
}

func cloneRepo(r repo, cloneDir string) error {
	dest := filepath.Join(cloneDir, r.name)
	if _, err := os.Stat(dest); err == nil {
		fmt.Printf("repo %q exists, skipping clone\n", r.name)
		return nil
	}
	fmt.Printf("cloning %s...\n", r.name)
	cmd := exec.Command("git", "clone", r.url, dest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// filterTools returns the subset of tools for which keep returns true,
// preserving order.
func filterTools(tools []string, keep func(string) bool) []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		if keep(t) {
			out = append(out, t)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Tool versions
// ---------------------------------------------------------------------------

var semverRe = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)

// collectVersions records each enabled tool's version string.
func collectVersions(tools []string) map[string]string {
	v := make(map[string]string, len(tools))
	for _, t := range tools {
		v[t] = toolVersion(t)
	}
	return v
}

// toolVersion runs the tool's version command and returns the semver it prints.
func toolVersion(tool string) string {
	var args []string
	switch tool {
	case toolKingfisher:
		args = []string{"kingfisher", "--version"}
	case toolTruffleHog:
		args = []string{"trufflehog", "--version"}
	case toolGitLeaks:
		args = []string{"gitleaks", "version"}
	default:
		return "unknown"
	}
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return "unknown"
	}
	if v := semverRe.FindString(string(out)); v != "" {
		return v
	}
	return strings.TrimSpace(string(out))
}

// ---------------------------------------------------------------------------
// Request-counting proxy
//
// Counts plain HTTP requests and HTTPS CONNECT tunnels sent through the proxy.
// TLS is forwarded without decryption, so requests inside a tunnel are not counted.
// ---------------------------------------------------------------------------

const proxyAddr = "127.0.0.1:9191"

// netReqCount counts requests intercepted since the last reset.
var netReqCount int64

type proxyHandler struct{}

func (p *proxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	atomic.AddInt64(&netReqCount, 1)
	if req.Method == http.MethodConnect {
		handleTunneling(w, req)
	} else {
		handleHTTP(w, req)
	}
}

// directTransport forwards straight to the destination, ignoring any
// HTTP_PROXY/HTTPS_PROXY in this process's environment. The default transport
// honors those vars, which on a corporate network would route the counting
// proxy's own forwards through an upstream proxy (or loop back into itself),
// skewing request counts. Built once so connections are still pooled.
var directTransport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return t
}()

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	// The incoming forward-proxy request already carries an absolute URL, so the
	// rewrite is a no-op: forward it as-is.
	proxy := httputil.ReverseProxy{
		Rewrite:   func(*httputil.ProxyRequest) {},
		Transport: directTransport,
	}
	proxy.ServeHTTP(w, req)
}

func handleTunneling(w http.ResponseWriter, req *http.Request) {
	destConn, err := net.Dial("tcp", req.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
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

// runProxy starts the counting proxy and blocks; run it in a goroutine.
func runProxy() {
	server := &http.Server{Addr: proxyAddr, Handler: &proxyHandler{}}
	log.Printf("Starting proxy on %s", proxyAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Proxy error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Scanners
//
// Each scanner runs an external tool against a repo through the counting proxy,
// saves the tool's raw output, and parses it into a ScanResult.
// ---------------------------------------------------------------------------

// commandLog records exact scanner argv and outcomes, outside measured runtimes.
// Scans are sequential, so command log writes do not need synchronization.
var commandLog io.Writer

// runScanCommand runs args with the proxy injected into the environment,
// directing stdout/stderr to the given writers (nil discards). It resets the
// proxy counter beforehand and returns how long the command took. A non-zero
// exit status is accepted only when it is a documented findings exit code.
func runScanCommand(args []string, stdout, stderr io.Writer, findingCodes ...int) (time.Duration, error) {
	atomic.StoreInt64(&netReqCount, 0)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "HTTP_PROXY=http://"+proxyAddr, "HTTPS_PROXY=http://"+proxyAddr,
		"http_proxy=http://"+proxyAddr, "https_proxy=http://"+proxyAddr)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)

	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			for _, code := range findingCodes {
				if exit.ExitCode() == code {
					err = nil
					break
				}
			}
		}
	}
	fmt.Fprintf(os.Stderr, "[TIME] %s took %.2fs\n", strings.Join(args, " "), elapsed.Seconds())
	if commandLog != nil {
		exitCode := -1
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
		if logErr := json.NewEncoder(commandLog).Encode(map[string]interface{}{
			"argv": args, "started_at": start.UTC().Format(time.RFC3339Nano),
			"duration_seconds": elapsed.Seconds(), "exit_code": exitCode, "error": scanError(err),
		}); logErr != nil {
			log.Printf("saving command log: %v", logErr)
		}
	}
	return elapsed, err
}

func scanError(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func scanKingfisher(repoPath, rawPath string, validate bool) ScanResult {
	f, err := os.Create(rawPath)
	if err != nil {
		log.Printf("kingfisher: %v", err)
		return ScanResult{Error: err.Error()}
	}
	var errBuf bytes.Buffer
	args := []string{"kingfisher", "scan", repoPath, "--format", "json",
		"--no-update-check", "--git-repo-timeout", "0", "--git-history", "full"}
	if !validate {
		args = append(args, "--no-validate")
	}
	d, runErr := runScanCommand(args, f, &errBuf, 200, 205)
	f.Close()
	os.WriteFile(rawPath+".stderr", errBuf.Bytes(), 0644)

	findings, validated, parseErr := parseKingfisherSummary(rawPath)
	if runErr == nil {
		runErr = parseErr
	}
	return ScanResult{Duration: d, Findings: findings, Validated: validated, NetReq: netReqSnapshot(), Error: scanError(runErr)}
}

func scanTruffleHog(repoPath, rawPath string, validate, inPlace bool) ScanResult {
	f, err := os.Create(rawPath)
	if err != nil {
		log.Printf("trufflehog: %v", err)
		return ScanResult{Error: err.Error()}
	}
	// Findings (NDJSON) go to stdout; the aggregate counts are in a summary log
	// line on stderr, which we capture to parse.
	var errBuf bytes.Buffer
	gitPath := filepath.ToSlash(repoPath)
	if !strings.HasPrefix(gitPath, "/") {
		gitPath = "/" + gitPath
	}
	gitURL := (&url.URL{Scheme: "file", Path: gitPath}).String()
	args := []string{"trufflehog", "git", gitURL, "--json", "--no-update", "--fail-on-scan-errors"}
	if inPlace {
		args = append(args, "--trust-local-git-config")
	}
	if !validate {
		args = append(args, "--no-verification")
	}
	d, runErr := runScanCommand(args, f, &errBuf)
	f.Close()
	os.WriteFile(rawPath+".stderr", errBuf.Bytes(), 0644)

	findings, verified := parseTruffleHogSummary(errBuf.String())
	return ScanResult{Duration: d, Findings: findings, Validated: verified, NetReq: netReqSnapshot(), Error: scanError(runErr)}
}

func scanGitleaks(repoPath, rawPath string) ScanResult {
	// GitLeaks writes its JSON report to --report-path itself.
	var errBuf bytes.Buffer
	d, runErr := runScanCommand([]string{"gitleaks", "git", repoPath, "--report-format", "json",
		"--report-path", rawPath, "--exit-code", "0", "--log-opts=--all --full-history"}, nil, &errBuf)
	os.WriteFile(rawPath+".stderr", errBuf.Bytes(), 0644)
	findings, parseErr := parseJSONArray(rawPath)
	if runErr == nil {
		runErr = parseErr
	}
	return ScanResult{Duration: d, Findings: findings, NetReq: netReqSnapshot(), Error: scanError(runErr)}
}

// netReqSnapshot returns the proxy's request count for the scan that just ran.
func netReqSnapshot() int64 { return atomic.LoadInt64(&netReqCount) }

// --- Output parsers ---

// parseKingfisherSummary reads current report metadata, falling back to finding
// records for envelopes without metadata and to legacy numeric summaries.
func parseKingfisherSummary(rawPath string) (findings, validated int, err error) {
	f, err := os.Open(rawPath)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	seen := false
	legacySeen := false
	legacyFindings, legacyValidated := 0, 0
	for {
		var envelope struct {
			Findings  json.RawMessage `json:"findings"`
			Validated int             `json:"successful_validations"`
			Metadata  *struct {
				Summary struct {
					Findings  int `json:"findings"`
					Validated int `json:"successful_validations"`
				} `json:"summary"`
			} `json:"metadata"`
		}
		if err := decoder.Decode(&envelope); err == io.EOF {
			break
		} else if err != nil {
			return 0, 0, err
		}
		seen = true
		if envelope.Metadata != nil {
			findings += envelope.Metadata.Summary.Findings
			validated += envelope.Metadata.Summary.Validated
			continue
		}
		var records []struct {
			Finding struct {
				Validation struct {
					Status string `json:"status"`
				} `json:"validation"`
			} `json:"finding"`
		}
		if json.Unmarshal(envelope.Findings, &records) == nil {
			findings += len(records)
			for _, record := range records {
				if record.Finding.Validation.Status == "Active Credential" {
					validated++
				}
			}
		} else {
			var count int
			if err := json.Unmarshal(envelope.Findings, &count); err != nil {
				return 0, 0, fmt.Errorf("invalid Kingfisher findings: %w", err)
			}
			// Some releases append an aggregate numeric summary after the report
			// envelope. It describes the same findings, so never add it twice.
			legacySeen = true
			legacyFindings, legacyValidated = count, envelope.Validated
		}
	}
	if !seen {
		return 0, 0, fmt.Errorf("empty Kingfisher output")
	}
	if legacySeen {
		return legacyFindings, legacyValidated, nil
	}
	return findings, validated, nil
}

// parseTruffleHogSummary finds the "finished scanning" log line (the only line
// carrying aggregate counts) in TruffleHog's stderr.
func parseTruffleHogSummary(stderr string) (findings, verified int) {
	scanner := bufio.NewScanner(strings.NewReader(stderr))
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		var d map[string]interface{}
		if json.Unmarshal(scanner.Bytes(), &d) != nil {
			continue
		}
		if u, ok := d["unverified_secrets"].(float64); ok {
			findings += int(u)
		}
		if v, ok := d["verified_secrets"].(float64); ok {
			verified += int(v)
			findings += int(v)
		}
	}
	return findings, verified
}

func parseJSONArray(reportPath string) (int, error) {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return 0, err
	}
	var arr []interface{}
	if err := json.Unmarshal(data, &arr); err != nil {
		return 0, err
	}
	return len(arr), nil
}

// ---------------------------------------------------------------------------
// Reporting (system info + Markdown report)
//
// Tables are generic over the list of enabled tools, so adding or removing a
// tool needs no table changes.
// ---------------------------------------------------------------------------

func getSystemInfo() string {
	mem := "N/A"
	switch runtime.GOOS {
	case "darwin":
		if out, err := exec.Command("sysctl", "-n", "hw.memsize").Output(); err == nil {
			if b, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); err == nil {
				mem = fmt.Sprintf("%.2f GB", float64(b)/(1024*1024*1024))
			}
		}
	case "linux":
		if data, err := os.ReadFile("/proc/meminfo"); err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(data))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "MemTotal:") {
					if parts := strings.Fields(line); len(parts) >= 2 {
						if kb, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
							mem = fmt.Sprintf("%.2f GB", float64(kb)/(1024*1024))
						}
					}
					break
				}
			}
		}
	}
	return fmt.Sprintf("OS: %s\nArchitecture: %s\nCPU Cores: %d\nRAM: %s\n",
		runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), mem)
}

// writeReport renders the full Markdown report to w.
func writeReport(w io.Writer, results []RepoResult, tools []string, versions map[string]string, chartFile, timestamp string, validate, trufflehogInPlace bool) {
	fmt.Fprintf(w, "# Kingfisher Benchmark — %s\n\n", timestamp)
	mode := "detection-only"
	if validate {
		mode = "validation-enabled"
	}
	fmt.Fprintf(w, "Validation mode: %s\n\nScan date: %s\n\nAnalysis month: %s\n\nTrials per tool per repository: %d\n\n",
		mode, dateFromTimestamp(timestamp), monthFromTimestamp(timestamp), trialCount)

	fmt.Fprintf(w, "## Environment\n\n```\n%s```\n\n", getSystemInfo())

	fmt.Fprintln(w, "## Tool Versions")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Tool | Version |")
	fmt.Fprintln(w, "|---|---|")
	for _, t := range tools {
		fmt.Fprintf(w, "| %s | %s |\n", t, versions[t])
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%d sequential trials per tool per repository, using existing clones and all available Git history (shallow status recorded below). The starting tool rotates each trial. Each metric reports its median across all %d trials. A failed or missing trial prevents a median for that tool and repository. Concurrency and detection settings retain each tool's defaults. Update checks are disabled where supported, and Kingfisher repository timeouts are disabled. Caches are kept in their normal state. Each tool's settings, filters, and deduplication affect its finding count.\n", trialCount, trialCount)
	if trufflehogInPlace {
		fmt.Fprintln(w, "TruffleHog scans the existing repositories directly with `--trust-local-git-config`.")
	} else {
		fmt.Fprintln(w, "TruffleHog's private clone preparation is included in its runtime.")
	}
	if validate {
		fmt.Fprintln(w, "Live validation/verification is enabled for Kingfisher and TruffleHog only. Use the same repository HEADs, refs, shallow state, and worktree state as the separate detection-only run; runtime charts are not generated for this mode.")
	} else {
		fmt.Fprintln(w, "Kingfisher validation and TruffleHog verification are explicitly disabled. Gitleaks is a detection-only scanner. These runtimes are the source for the runtime comparison chart.")
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Reproducibility")
	fmt.Fprintln(w)
	config := make(map[string]string)
	flag.VisitAll(func(f *flag.Flag) { config[f.Name] = f.Value.String() })
	configJSON, _ := json.MarshalIndent(config, "", "  ")
	argvJSON, _ := json.Marshal(os.Args)
	fmt.Fprintf(w, "Effective run flags (including defaults):\n\n```json\n%s\n```\n\nInvocation: `%s`\n\n", configJSON, argvJSON)
	fmt.Fprintln(w, "Input metadata is captured before scanning. An empty worktree_status means clean; refs_sha256 hashes sorted ref names and object IDs. Status alone does not fingerprint modified file contents. Compare metadata across modes and leave clones unchanged during both runs. Actual scanner commands and timings are printed in [TIME] logs; [commands.jsonl](commands.jsonl) records exact argument arrays, timestamps, durations, exit codes, and errors.")
	for _, r := range results {
		metadataJSON, _ := json.MarshalIndent(r.Metadata, "", "  ")
		fmt.Fprintf(w, "\n### %s input\n\n```json\n%s\n```\n\nRaw data sources (%s):\n", r.Repo, metadataJSON, mode)
		for _, tool := range tools {
			fmt.Fprintf(w, "- %s", tool)
			for trial := 1; trial <= trialCount; trial++ {
				name := trialFilename(r.Repo, tool, trial)
				fmt.Fprintf(w, " · [%d](%s) ([stderr](%s.stderr))", trial, name, name)
			}
			fmt.Fprintln(w)
		}
	}
	fmt.Fprintln(w)

	runtimeHeading := "Runtime Comparison (seconds) — lower is better"
	if validate {
		runtimeHeading = "Validation-enabled Runtime (seconds)"
	}
	writeTable(w, runtimeHeading, " Runtime", results, tools,
		func(s ScanResult) string { return fmt.Sprintf("%.2f", s.Duration.Seconds()) })

	writeTable(w, "Findings Comparison", " Findings", results, tools,
		func(s ScanResult) string { return strconv.Itoa(s.Findings) })

	if validate {
		validating := filterTools(tools, canValidate)
		writeTable(w, "Validated / Verified Findings", " Validated", results, validating,
			func(s ScanResult) string { return strconv.Itoa(s.Validated) })
		writeTable(w, "Network Requests Comparison", " Network Requests", results, validating,
			func(s ScanResult) string { return strconv.FormatInt(s.NetReq, 10) })
		fmt.Fprintln(w, "'Network Requests' counts plain HTTP requests and HTTPS CONNECT tunnels observed by the proxy; TLS requests inside tunnels and traffic bypassing the proxy are not counted.")
	}

	if !validate {
		if chartFile != "" {
			fmt.Fprintf(w, "![Runtime comparison](%s)\n\n", chartFile)
		}
		fmt.Fprintln(w, "Chart annotations compare Kingfisher with the fastest successful competing tool for each repository. Failed scans are omitted from the chart.")
	}
	fmt.Fprintln(w, "\nFailed scans are marked ERROR. Raw stderr logs are saved alongside each JSON report.")
	for _, r := range results {
		for _, tool := range tools {
			if s := r.Scans[tool]; s.Error != "" {
				fmt.Fprintf(w, "\n- %s / %s: %s\n", r.Repo, tool, s.Error)
			}
		}
	}
}

// canValidate reports whether a tool produces validated/verified counts.
func canValidate(t string) bool { return t == toolKingfisher || t == toolTruffleHog }

// writeTable writes a section heading and a Markdown table with one row per
// repo. cell extracts the value for a given tool's ScanResult.
func writeTable(w io.Writer, heading, headerSuffix string, results []RepoResult, tools []string, cell func(ScanResult) string) {
	fmt.Fprintf(w, "## %s\n\n", heading)

	cols := append([]string{"Repository"}, suffixed(tools, headerSuffix)...)
	fmt.Fprintln(w, "| "+strings.Join(cols, " | ")+" |")
	seps := make([]string, len(cols))
	for i := range seps {
		seps[i] = "---"
	}
	fmt.Fprintln(w, "|"+strings.Join(seps, "|")+"|")

	for _, r := range results {
		row := make([]string, 0, len(tools)+1)
		row = append(row, r.Repo)
		for _, t := range tools {
			if s := r.Scans[t]; s.Error != "" {
				row = append(row, "ERROR")
			} else {
				row = append(row, cell(s))
			}
		}
		fmt.Fprintln(w, "| "+strings.Join(row, " | ")+" |")
	}
	fmt.Fprintln(w)
}

// suffixed appends suffix to each tool name.
func suffixed(tools []string, suffix string) []string {
	out := make([]string, len(tools))
	for i, t := range tools {
		out[i] = t + suffix
	}
	return out
}

// ---------------------------------------------------------------------------
// Chart generation
//
// Renders a grouped-bar "Runtime comparison" PNG via the QuickChart.io render
// API (Chart.js v4), matching docs/runtime-comparison.png. Each Kingfisher bar
// is annotated with how much faster or slower it is than the fastest competing tool, with
// a downward arrow pointing at Kingfisher's bar.
// ---------------------------------------------------------------------------

const quickChartURL = "https://quickchart.io/chart"

const (
	scanDateLayout      = "January 2, 2006"
	analysisMonthLayout = "January 2006"
	toolNoseyParker     = "NoseyParker" // Optional series from a comparable, separate benchmark.
)

// toolColors maps each tool to its bar color, matching the reference chart.
var toolColors = map[string]string{
	toolKingfisher:  "#01ec64", // green
	toolTruffleHog:  "#4a85e8", // blue
	toolGitLeaks:    "#fabd05", // amber
	toolNoseyParker: "#4a85e8", // blue in the head-to-head chart
}

// buildRuntimeChartConfig matches the reference chart's dimensions, typography,
// colors, outlined Kingfisher bars, and straight downward arrow annotations.
func buildRuntimeChartConfig(results []RepoResult, tools []string, versions map[string]string, subtitle string) string {
	title := "Runtime comparison"
	footer := "Based on results of internal testing conducted by MongoDB engineering"
	headToHead := len(tools) == 2 && tools[1] == toolNoseyParker
	if headToHead {
		title = "Kingfisher vs. NoseyParker"
		footer = "* Kingfisher extracts and scans archives and decodes Base64. NoseyParker ran without those steps."
	}
	labels := make([]string, len(results))
	maxSeconds := 1.0
	for i, r := range results {
		labels[i] = r.Repo
		for _, scan := range r.Scans {
			if scan.Error == "" && scan.Duration.Seconds() > maxSeconds {
				maxSeconds = scan.Duration.Seconds()
			}
		}
	}
	labelsJSON, _ := json.Marshal(labels)
	versionLabels := make([]string, len(tools))
	for i, tool := range tools {
		version := strings.TrimSpace(versions[tool])
		if tool == toolKingfisher && semverRe.MatchString(version) {
			version = strings.TrimPrefix(version, "v")
			if parts := strings.Split(version, "."); len(parts) == 3 && parts[2] == "0" {
				version = strings.Join(parts[:2], ".")
			}
		} else if semverRe.MatchString(version) && !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
		if version == "" {
			version = "unknown"
		}
		versionLabels[i] = version
	}
	datasets := make([]string, 0, len(tools))
	for _, tool := range tools {
		secs := make([]interface{}, len(results))
		for i, r := range results {
			if scan, ok := r.Scans[tool]; ok && scan.Error == "" {
				secs[i] = scan.Duration.Seconds()
			}
		}
		values, _ := json.Marshal(secs)
		border := 0
		if tool == toolKingfisher {
			border = 2
		}
		datasets = append(datasets, fmt.Sprintf(
			`{"label":%q,"data":%s,"backgroundColor":%q,"borderColor":"#011e2a","borderWidth":%d,"borderRadius":3,"borderSkipped":"bottom","categoryPercentage":0.6,"barPercentage":0.94}`,
			tool, values, toolColors[tool], border))
	}
	// Leave enough room above every Kingfisher bar for the reference-style arrow.
	upper := maxSeconds
	for _, r := range results {
		if r.Scans[toolKingfisher].Error == "" {
			upper = math.Max(upper, r.Scans[toolKingfisher].Duration.Seconds()+maxSeconds*0.32)
		}
	}
	step := math.Pow(10, math.Floor(math.Log10(upper/3)))
	for _, factor := range []float64{1, 2, 5, 10} {
		if upper/(step*factor) <= 5 {
			step *= factor
			break
		}
	}
	ceiling := upper + step*0.1
	annotations := make([]string, 0, len(results))
	kingfisherIndex := slices.Index(tools, toolKingfisher)
	for i, r := range results {
		pct, ok := kingfisherSpeedup(r, tools)
		if !ok {
			continue
		}
		x := float64(i) - 0.6/2 + 0.6*(float64(kingfisherIndex)+0.5)/float64(len(tools))
		y := r.Scans[toolKingfisher].Duration.Seconds()
		highest := y
		for _, tool := range tools {
			if scan := r.Scans[tool]; scan.Error == "" {
				highest = math.Max(highest, scan.Duration.Seconds())
			}
		}
		// Put labels above nearby bars; when that would exceed the chart, move
		// the label left of its arrow, as in the reference's Linux annotation.
		arrowTop := math.Max(y+ceiling*0.2, highest+ceiling*0.025)
		labelOffset := 0
		if arrowTop > ceiling*0.9 {
			arrowTop = math.Max(y+ceiling*0.2, ceiling*0.6)
			labelOffset = -45
		}
		annotations = append(annotations, fmt.Sprintf(`"arrow%d":{
   type:'line',xMin:%f,xMax:%f,yMin:%f,yMax:%f,
   borderColor:'#011e2a',borderWidth:1.6,
   arrowHeads:{start:{display:true,length:16,width:6,fill:true}}
  }`, i, x, x, y+ceiling*0.008, arrowTop))
		addLabel := func(id, content string, size, vertical int, horizontal float64, weight string) {
			annotations = append(annotations, fmt.Sprintf(`"%s%d":{
   type:'label',xValue:%f,yValue:%f,adjustScaleRange:false,
   xAdjust:%f,yAdjust:%d,padding:0,content:%q,
   backgroundColor:'transparent',color:'#011e2a',font:{family:'Noto Sans',size:%d,weight:%q}
  }`, id, i, x, arrowTop, float64(labelOffset)+horizontal, vertical, content, size, weight))
		}
		addLabel("scanner", "Kingfisher", 18, -39, 0, "normal")
		switch {
		case pct > 0:
			// Separate the number and the word so only "faster" is bold.
			// At this font size digits take about 8.6 px and the percent sign 12.5 px.
			percentage := fmt.Sprintf("%.0f%%", pct)
			percentageWidth := 8.6*float64(len(percentage)-1) + 12.5
			addLabel("percentage", percentage, 15, -18, -22.5, "normal")
			addLabel("faster", "faster", 15, -18, (percentageWidth+4)/2, "bold")
		case pct < 0:
			addLabel("slower", fmt.Sprintf("%.0f%% slower", -pct), 15, -18, 0, "normal")
		default:
			addLabel("equal", "Same runtime", 15, -18, 0, "normal")
		}
	}
	// Built-in annotations support multi-line legends on QuickChart Community,
	// whose sandbox does not expose canvas methods to custom drawing plugins.
	legendWidths := make([]float64, len(tools))
	legendWidth := -28.0
	for i, tool := range tools {
		legendWidths[i] = 32 + math.Max(float64(len(tool))*11.7, float64(len(versionLabels[i]))*8)
		legendWidth += legendWidths[i] + 28
	}
	left := (1360 - legendWidth) / 2
	middle := float64(len(results)-1) / 2
	for i, tool := range tools {
		textCenter := left + 32 + (legendWidths[i]-32)/2
		legendName := tool
		if headToHead && tool == toolKingfisher {
			legendName += "*"
		}
		content, _ := json.Marshal([]string{legendName, versionLabels[i]})
		border := 0
		if tool == toolKingfisher {
			border = 2
		}
		annotations = append(annotations, fmt.Sprintf(`"legendText%d":{
   type:'label',xValue:%f,yValue:0,adjustScaleRange:false,
   xAdjust:function(c){return %f-(c.chart.chartArea.left+c.chart.chartArea.right)/2;},
   yAdjust:function(c){return c.chart.chartArea.top-36-c.chart.chartArea.bottom;},
   content:%s,font:[{family:'Noto Sans',size:20},{family:'Noto Sans',size:16}],backgroundColor:'transparent',color:'#274553'
  },"legendSymbol%d":{
   type:'box',adjustScaleRange:false,
   xMin:function(c){return (%f-c.chart.chartArea.left)/(c.chart.chartArea.right-c.chart.chartArea.left)*%d-0.5;},
   xMax:function(c){return (%f-c.chart.chartArea.left)/(c.chart.chartArea.right-c.chart.chartArea.left)*%d-0.5;},
   yMin:function(c){return %f*(1+35/(c.chart.chartArea.bottom-c.chart.chartArea.top));},
   yMax:function(c){return %f*(1+57/(c.chart.chartArea.bottom-c.chart.chartArea.top));},
   backgroundColor:%q,borderColor:'#011e2a',borderWidth:%d,borderRadius:3
  }`, i, middle, textCenter, content, i, left, len(results), left+22, len(results), ceiling, ceiling, toolColors[tool], border))
		left += legendWidths[i] + 28
	}
	annotations = append(annotations, fmt.Sprintf(`"footer":{
   type:'label',xValue:%f,yValue:0,adjustScaleRange:false,
   yAdjust:function(c){return c.chart.height-c.chart.chartArea.bottom-12;},
   content:%q,
   backgroundColor:'transparent',color:'#274553',font:{family:'DejaVu Sans',size:15},drawTime:'afterDraw'
  }`, middle, footer))
	return fmt.Sprintf(`{
  type:'bar',
  data:{labels:%s,datasets:[%s]},
  options:{
   layout:{padding:{top:0,right:34,bottom:42,left:0}},
   plugins:{
    title:{display:true,fullSize:false,text:%q,font:{size:52,family:'Georgia',weight:'normal'},color:'#011e2a',padding:{top:-6,bottom:8}},
    subtitle:{display:true,fullSize:false,position:'top',text:%q,color:'#274553',font:{family:'Noto Sans',size:20,weight:'normal'},padding:{top:0,bottom:68}},
    legend:{display:false},
    datalabels:{display:false},
    annotation:{clip:false,annotations:{%s}}
   },
   scales:{
    x:{title:{display:true,text:'Repository',font:{family:'DejaVu Sans',size:36,weight:'normal'},color:'#011e2a',padding:{top:8}},grid:{display:false},border:{color:'#9d9d9d',width:1.5},ticks:{font:{family:'DejaVu Sans',size:20},color:'#274553',maxRotation:0,autoSkip:false}},
    y:{beginAtZero:true,max:%f,title:{display:true,text:'Runtime in seconds',font:{family:'DejaVu Sans',size:36,weight:'normal'},color:'#011e2a',padding:{bottom:46}},ticks:{stepSize:%f,includeBounds:false,font:{family:'DejaVu Sans',size:20},color:'#274553'},border:{display:false},grid:{color:'#d4d4d4',lineWidth:1.5}}
   }
  }
 }`, labelsJSON, strings.Join(datasets, ","), title, subtitle, strings.Join(annotations, ","), ceiling, step)
}

// kingfisherSpeedup returns how much faster Kingfisher was than the fastest
// other tool for this repo. ok is false when there's nothing to compare.
func kingfisherSpeedup(r RepoResult, tools []string) (pct float64, ok bool) {
	kf := r.Scans[toolKingfisher].Duration.Seconds()
	fastest := math.Inf(1)
	for _, t := range tools {
		if t == toolKingfisher {
			continue
		}
		if s := r.Scans[t]; s.Error == "" && s.Duration > 0 && s.Duration.Seconds() < fastest {
			fastest = s.Duration.Seconds()
		}
	}
	if math.IsInf(fastest, 1) || kf <= 0 || r.Scans[toolKingfisher].Error != "" {
		return 0, false
	}
	if kf > fastest {
		return -(kf/fastest - 1) * 100, true
	}
	return (fastest - kf) / fastest * 100, true
}

// regenerateChart rebuilds the runtime chart from a previous run's report,
// writing a fresh runtime-comparison-<timestamp>.png into the same directory.
func regenerateChart(dir string, includeNoseyParker bool) error {
	results, tools, versions, subtitle, err := loadResultsFromReport(dir, includeNoseyParker)
	if err != nil {
		return err
	}
	name := "runtime-comparison-" + time.Now().Format("20060102-150405")
	if includeNoseyParker {
		name += "-with-nosey-parker"
	}
	name += ".png"
	outPath := filepath.Join(dir, name)
	if err := renderChartPNG(buildRuntimeChartConfig(results, tools, versions, subtitle), outPath); err != nil {
		return err
	}
	fmt.Printf("Chart written to %s\n", outPath)
	return nil
}

// monthFromTimestamp never uses the regeneration clock to date saved results.
func monthFromTimestamp(timestamp string) string {
	date, err := time.Parse("20060102-150405", timestamp)
	if err != nil {
		return ""
	}
	return date.Format(analysisMonthLayout)
}

func dateFromTimestamp(timestamp string) string {
	date, err := time.Parse("20060102-150405", timestamp)
	if err != nil {
		return ""
	}
	return date.Format(scanDateLayout)
}

func runtimeChartSubtitle(month string, trials int) string {
	if trials == 0 {
		return month
	}
	return fmt.Sprintf("%s · Median of %d trials per tool per repository", month, trials)
}

// chartReportTool accepts the name used in saved reports before the renderer
// standardized on NoseyParker.
func chartReportTool(name string) string {
	if name == "Nosey Parker" {
		return toolNoseyParker
	}
	return name
}

// loadResultsFromReport reconstructs chart runtimes, tool order, versions, and
// the subtitle from the comparison_<timestamp>.md report in dir. The head-to-head
// uses the normal Kingfisher scan configuration and the comparable NoseyParker
// timings.
func loadResultsFromReport(dir string, includeNoseyParker bool) ([]RepoResult, []string, map[string]string, string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "comparison_*.md"))
	if err != nil || len(matches) == 0 {
		return nil, nil, nil, "", fmt.Errorf("no comparison_*.md report found in %s", dir)
	}
	if len(matches) != 1 {
		return nil, nil, nil, "", fmt.Errorf("expected exactly one comparison report in %s; found %d", dir, len(matches))
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		return nil, nil, nil, "", err
	}
	lines := strings.Split(string(data), "\n")
	modeCount := 0
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "Validation mode:") {
			modeCount++
			if strings.TrimSpace(line) != "Validation mode: detection-only" {
				return nil, nil, nil, "", fmt.Errorf("%s is not explicitly detection-only; refusing runtime chart", matches[0])
			}
		}
	}
	if modeCount != 1 {
		return nil, nil, nil, "", fmt.Errorf("%s must declare exactly one 'Validation mode: detection-only'; refusing legacy or ambiguous runtime data", matches[0])
	}

	scanMonth := ""
	analysisMonth := ""
	trials := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if value, ok := strings.CutPrefix(line, "Scan date:"); ok {
			date, err := time.Parse(scanDateLayout, strings.TrimSpace(value))
			if err != nil || scanMonth != "" {
				return nil, nil, nil, "", fmt.Errorf("invalid or repeated Scan date in %s", matches[0])
			}
			scanMonth = date.Format(analysisMonthLayout)
		}
		if value, ok := strings.CutPrefix(line, "Analysis month:"); ok {
			date, err := time.Parse(analysisMonthLayout, strings.TrimSpace(value))
			if err != nil || analysisMonth != "" {
				return nil, nil, nil, "", fmt.Errorf("invalid or repeated Analysis month in %s", matches[0])
			}
			analysisMonth = date.Format(analysisMonthLayout)
		}
		if value, ok := strings.CutPrefix(line, "Trials per tool per repository:"); ok {
			count, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || count < 1 || trials != 0 {
				return nil, nil, nil, "", fmt.Errorf("invalid or repeated trial count in %s", matches[0])
			}
			trials = count
		}
	}
	if scanMonth == "" {
		scanMonth = analysisMonth
	}
	if scanMonth == "" {
		for _, line := range lines {
			if strings.HasPrefix(line, "# ") {
				if timestamp := regexp.MustCompile(`\b\d{8}-\d{6}\b`).FindString(line); timestamp != "" {
					scanMonth = monthFromTimestamp(timestamp)
					break
				}
			}
		}
	}
	if scanMonth == "" {
		return nil, nil, nil, "", fmt.Errorf("Scan date, Analysis month, or dated report header required in %s", matches[0])
	}

	// Runtime table: header columns are "<Tool> Runtime"; rows are "<repo> <secs>...".
	rtHeader, rtRows := markdownTable(lines, "## Runtime Comparison")
	if len(rtHeader) < 2 {
		return nil, nil, nil, "", fmt.Errorf("runtime table not found in %s", matches[0])
	}
	if len(rtRows) == 0 {
		return nil, nil, nil, "", fmt.Errorf("runtime table has no repositories in %s", matches[0])
	}
	tools := make([]string, 0, len(rtHeader)-1)
	columns := make(map[string]int, len(rtHeader)-1)
	for i, h := range rtHeader[1:] {
		tool := chartReportTool(strings.TrimSpace(strings.TrimSuffix(h, "Runtime")))
		if _, known := toolColors[tool]; !known {
			return nil, nil, nil, "", fmt.Errorf("unsupported runtime tool column %q in %s", h, matches[0])
		}
		if _, exists := columns[tool]; exists {
			return nil, nil, nil, "", fmt.Errorf("repeated %s runtime column in %s", tool, matches[0])
		}
		columns[tool] = i + 1
		if tool != toolNoseyParker {
			tools = append(tools, tool)
		}
	}
	if includeNoseyParker {
		tools = []string{toolKingfisher, toolNoseyParker}
		for _, tool := range tools {
			if _, ok := columns[tool]; !ok {
				return nil, nil, nil, "", fmt.Errorf("%s runtime column required with -nosey-parker-chart in %s", tool, matches[0])
			}
		}
	}
	results := make([]RepoResult, 0, len(rtRows))
	for _, row := range rtRows {
		rr := RepoResult{Repo: row[0], Scans: make(map[string]ScanResult, len(tools))}
		for _, t := range tools {
			if columns[t] >= len(row) {
				return nil, nil, nil, "", fmt.Errorf("missing %s runtime cell for %s in %s", t, rr.Repo, matches[0])
			}
			cell := row[columns[t]]
			secs, err := strconv.ParseFloat(cell, 64)
			if err != nil || math.IsNaN(secs) || math.IsInf(secs, 0) || secs <= 0 {
				if t == toolNoseyParker {
					return nil, nil, nil, "", fmt.Errorf("successful %s runtime required for %s in %s", t, rr.Repo, matches[0])
				}
				rr.Scans[t] = ScanResult{Error: "runtime unavailable"}
			} else {
				rr.Scans[t] = ScanResult{Duration: time.Duration(secs * float64(time.Second))}
			}
		}
		results = append(results, rr)
	}

	// Versions table (optional).
	versions := make(map[string]string, len(tools))
	if _, vRows := markdownTable(lines, "## Tool Versions"); vRows != nil {
		for _, row := range vRows {
			if len(row) >= 2 {
				versions[chartReportTool(row[0])] = row[1]
			}
		}
	}
	if includeNoseyParker && strings.TrimSpace(versions[toolNoseyParker]) == "" {
		return nil, nil, nil, "", fmt.Errorf("%s version required in %s", toolNoseyParker, matches[0])
	}
	return results, tools, versions, runtimeChartSubtitle(scanMonth, trials), nil
}

// markdownTable returns the header cells and data rows of the first Markdown
// table appearing after the given heading line.
func markdownTable(lines []string, heading string) (header []string, rows [][]string) {
	i := 0
	for ; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], heading) {
			break
		}
	}
	for ; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "|") {
			break
		}
	}
	if i >= len(lines) {
		return nil, nil
	}
	header = splitTableRow(lines[i])
	i++
	if i < len(lines) && strings.Contains(lines[i], "---") {
		i++ // skip separator
	}
	for ; i < len(lines); i++ {
		if !strings.HasPrefix(strings.TrimSpace(lines[i]), "|") {
			break
		}
		rows = append(rows, splitTableRow(lines[i]))
	}
	return header, rows
}

// splitTableRow splits a Markdown table row into trimmed cell values.
func splitTableRow(line string) []string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// renderChartPNG posts the config to QuickChart and writes the returned PNG.
func renderChartPNG(config, outPath string) error {
	body, _ := json.Marshal(map[string]interface{}{
		"chart":            config,
		"width":            1360,
		"height":           966,
		"format":           "png",
		"backgroundColor":  "white",
		"version":          "4",
		"devicePixelRatio": 1,
	})

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(quickChartURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("quickchart returned %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return os.WriteFile(outPath, data, 0644)
}
