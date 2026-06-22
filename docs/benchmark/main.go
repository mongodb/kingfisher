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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
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
)

// ScanResult holds the metrics captured for a single tool scanning a single repo.
type ScanResult struct {
	Duration  time.Duration
	Findings  int   // total findings reported
	Validated int   // validated/verified findings (0 when the tool can't validate)
	NetReq    int64 // HTTP requests observed by the proxy during the scan
}

// RepoResult aggregates every tool's ScanResult for one repository.
type RepoResult struct {
	Repo  string
	Scans map[string]ScanResult
}

// ---------------------------------------------------------------------------
// Entry point & orchestration
// ---------------------------------------------------------------------------

func main() {
	baseDir := flag.String("basedir", "", "directory to clone repos into (default: $TMPDIR/benchmark)")
	withGitleaks := flag.Bool("gitleaks", false, "include GitLeaks in the benchmark (requires gitleaks in PATH)")
	makeChart := flag.Bool("chart", true, "render a runtime-comparison PNG chart")
	outRoot := flag.String("out", ".", "directory under which the timestamped results folder is created")
	chartFrom := flag.String("chart-from", "", "regenerate only the chart from an existing benchmark-<timestamp> directory, then exit")
	flag.Parse()

	// Chart-only mode: rebuild the PNG from a previous run's report and exit
	// without cloning or scanning anything.
	if *chartFrom != "" {
		if err := regenerateChart(*chartFrom); err != nil {
			log.Fatalf("regenerating chart: %v", err)
		}
		return
	}

	cloneDir := *baseDir
	if cloneDir == "" {
		cloneDir = filepath.Join(os.TempDir(), "benchmark")
	}
	if err := os.MkdirAll(cloneDir, 0755); err != nil {
		log.Fatalf("creating clone dir: %v", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	outDir := filepath.Join(*outRoot, "benchmark-"+timestamp)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("creating results dir: %v", err)
	}

	tools := enabledTools(*withGitleaks)
	versions := collectVersions(tools)

	go runProxy()
	time.Sleep(500 * time.Millisecond)

	fmt.Println(getSystemInfo())

	// Phase 1: clone everything up front. A repo that fails to clone (e.g. a
	// transient remote error) is skipped with a warning rather than aborting the
	// run, so the scans we can do still complete.
	fmt.Println("=== Cloning repositories ===")
	ready := make([]repo, 0, len(repos))
	for _, r := range repos {
		if err := cloneRepo(r, cloneDir); err != nil {
			log.Printf("skipping %s: clone failed: %v", r.name, err)
			continue
		}
		ready = append(ready, r)
	}

	// Phase 2: scan every successfully-cloned repo with all enabled tools.
	fmt.Println("\n=== Scanning ===")
	results := make([]RepoResult, 0, len(ready))
	for _, r := range ready {
		results = append(results, scanRepo(r, cloneDir, outDir, tools))
	}

	// Render the chart (into the results dir) before writing the report, so the
	// report can link to it.
	chartFile := ""
	if *makeChart {
		name := "runtime-comparison-" + timestamp + ".png"
		config := buildRuntimeChartConfig(results, tools, versions)
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
	writeReport(io.MultiWriter(os.Stdout, mdFile), results, tools, versions, chartFile, timestamp)
	mdFile.Close()

	fmt.Printf("\nResults written to %s/\n", outDir)
}

// enabledTools returns the ordered list of tools to run. GitLeaks is included
// only when requested and present in PATH.
func enabledTools(withGitleaks bool) []string {
	tools := []string{toolKingfisher, toolTruffleHog}
	if withGitleaks {
		if _, err := exec.LookPath("gitleaks"); err == nil {
			tools = append(tools, toolGitLeaks)
		} else {
			log.Printf("gitleaks requested but not found in PATH; skipping it")
		}
	}
	return tools
}

// scanRepo runs every enabled tool against a single repo, saving each tool's raw
// output into outDir as <repo>-<tool>.json.
func scanRepo(r repo, cloneDir, outDir string, tools []string) RepoResult {
	repoPath := filepath.Join(cloneDir, r.name)
	res := RepoResult{Repo: r.name, Scans: make(map[string]ScanResult, len(tools))}
	for _, tool := range tools {
		fmt.Printf("[%s] scanning %s...\n", tool, repoPath)
		rawPath := filepath.Join(outDir, fmt.Sprintf("%s-%s.json", r.name, strings.ToLower(tool)))
		switch tool {
		case toolKingfisher:
			res.Scans[tool] = scanKingfisher(repoPath, rawPath)
		case toolTruffleHog:
			res.Scans[tool] = scanTruffleHog(repoPath, rawPath)
		case toolGitLeaks:
			res.Scans[tool] = scanGitleaks(repoPath, rawPath)
		}
	}
	return res
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
// A minimal intercepting HTTP/HTTPS proxy that counts every request a scanning
// tool makes. It does not decrypt TLS; CONNECT tunnels are blind-forwarded.
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

// runScanCommand runs args with the proxy injected into the environment,
// directing stdout/stderr to the given writers (nil discards). It resets the
// proxy counter beforehand and returns how long the command took. A non-zero
// exit status is expected from these tools (they exit non-zero when they find
// secrets) and is not treated as an error.
func runScanCommand(args []string, stdout, stderr io.Writer) time.Duration {
	atomic.StoreInt64(&netReqCount, 0)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "HTTP_PROXY=http://"+proxyAddr, "HTTPS_PROXY=http://"+proxyAddr)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)

	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			log.Printf("%s: %v", args[0], err)
		}
	}
	fmt.Fprintf(os.Stderr, "[TIME] %s took %.2fs\n", strings.Join(args, " "), elapsed.Seconds())
	return elapsed
}

func scanKingfisher(repoPath, rawPath string) ScanResult {
	f, err := os.Create(rawPath)
	if err != nil {
		log.Printf("kingfisher: %v", err)
		return ScanResult{}
	}
	// JSON findings go to stdout; the pretty summary goes to stderr (discarded).
	d := runScanCommand([]string{"kingfisher", "scan", repoPath, "--format", "json"}, f, nil)
	f.Close()

	findings, validated := parseKingfisherSummary(rawPath)
	return ScanResult{Duration: d, Findings: findings, Validated: validated, NetReq: netReqSnapshot()}
}

func scanTruffleHog(repoPath, rawPath string) ScanResult {
	f, err := os.Create(rawPath)
	if err != nil {
		log.Printf("trufflehog: %v", err)
		return ScanResult{}
	}
	// Findings (NDJSON) go to stdout; the aggregate counts are in a summary log
	// line on stderr, which we capture to parse.
	var errBuf bytes.Buffer
	d := runScanCommand([]string{"trufflehog", "git", "file://" + repoPath, "--json"}, f, &errBuf)
	f.Close()

	findings, verified := parseTruffleHogSummary(errBuf.String())
	return ScanResult{Duration: d, Findings: findings, Validated: verified, NetReq: netReqSnapshot()}
}

func scanGitleaks(repoPath, rawPath string) ScanResult {
	// GitLeaks writes its JSON report to --report-path itself.
	d := runScanCommand([]string{"gitleaks", "git", "-v", repoPath, "--report-path", rawPath}, nil, nil)
	return ScanResult{Duration: d, Findings: parseGitleaksOutput(rawPath), NetReq: netReqSnapshot()}
}

// netReqSnapshot returns the proxy's request count for the scan that just ran.
func netReqSnapshot() int64 { return atomic.LoadInt64(&netReqCount) }

// --- Output parsers ---

// parseKingfisherSummary reads the trailing summary object from Kingfisher's
// JSON output (the last line; the first line is the full findings array, which
// can be very large, so we only read the tail).
func parseKingfisherSummary(rawPath string) (findings, validated int) {
	line, err := lastLine(rawPath)
	if err != nil {
		return 0, 0
	}
	var d map[string]interface{}
	if json.Unmarshal(line, &d) != nil {
		return 0, 0
	}
	if v, ok := d["findings"].(float64); ok {
		findings = int(v)
	}
	if v, ok := d["successful_validations"].(float64); ok {
		validated = int(v)
	}
	return findings, validated
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

func parseGitleaksOutput(reportPath string) int {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return 0
	}
	var arr []interface{}
	if json.Unmarshal(data, &arr) != nil {
		return 0
	}
	return len(arr)
}

// lastLine returns the final non-empty line of a file, reading from the end so
// it stays cheap even when earlier lines are huge.
func lastLine(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const chunk = 64 * 1024
	var buf []byte
	pos := fi.Size()
	for pos > 0 {
		n := int64(chunk)
		if pos < n {
			n = pos
		}
		pos -= n
		b := make([]byte, n)
		if _, err := f.ReadAt(b, pos); err != nil && err != io.EOF {
			return nil, err
		}
		buf = append(b, buf...)
		trimmed := bytes.TrimRight(buf, "\r\n")
		if i := bytes.LastIndexByte(trimmed, '\n'); i >= 0 {
			return trimmed[i+1:], nil
		}
	}
	return bytes.TrimRight(buf, "\r\n"), nil
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
func writeReport(w io.Writer, results []RepoResult, tools []string, versions map[string]string, chartFile, timestamp string) {
	fmt.Fprintf(w, "# Kingfisher Benchmark — %s\n\n", timestamp)

	fmt.Fprintf(w, "## Environment\n\n```\n%s```\n\n", getSystemInfo())

	fmt.Fprintln(w, "## Tool Versions")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Tool | Version |")
	fmt.Fprintln(w, "|---|---|")
	for _, t := range tools {
		fmt.Fprintf(w, "| %s | %s |\n", t, versions[t])
	}
	fmt.Fprintln(w)

	writeTable(w, "Runtime Comparison (seconds) — lower is better", " Runtime", results, tools,
		func(s ScanResult) string { return fmt.Sprintf("%.2f", s.Duration.Seconds()) })

	writeTable(w, "Findings Comparison", " Findings", results, tools,
		func(s ScanResult) string { return strconv.Itoa(s.Findings) })

	if validating := filterTools(tools, canValidate); len(validating) > 0 {
		writeTable(w, "Validated / Verified Findings", " Validated", results, validating,
			func(s ScanResult) string { return strconv.Itoa(s.Validated) })
	}

	writeTable(w, "Network Requests Comparison", " Network Requests", results, tools,
		func(s ScanResult) string { return strconv.FormatInt(s.NetReq, 10) })

	if chartFile != "" {
		fmt.Fprintf(w, "![Runtime comparison](%s)\n\n", chartFile)
	}

	fmt.Fprintln(w, "*Lower runtimes are better. Validated/Verified counts are reported where available. "+
		"'Network Requests' is the number of HTTP requests each tool made during scanning.*")
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
			row = append(row, cell(r.Scans[t]))
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
// is annotated with how much faster it is than the slowest competing tool, with
// a downward arrow pointing at the (shorter, better) bar.
// ---------------------------------------------------------------------------

const quickChartURL = "https://quickchart.io/chart"

// toolColors maps each tool to its bar color, matching the reference chart.
var toolColors = map[string]string{
	toolKingfisher: "#21c95a", // green
	toolTruffleHog: "#4d8ef7", // blue
	toolGitLeaks:   "#ffc01e", // amber
}

// buildRuntimeChartConfig returns a Chart.js config string. It is not strict
// JSON: the datalabels plugin needs JS function expressions, so the config is
// assembled as JS source and sent to QuickChart as such.
func buildRuntimeChartConfig(results []RepoResult, tools []string, versions map[string]string) string {
	labels := make([]string, len(results))
	for i, r := range results {
		labels[i] = r.Repo
	}
	labelsJSON, _ := json.Marshal(labels)

	datasets := make([]string, 0, len(tools))
	for _, tool := range tools {
		secs := make([]float64, len(results))
		for i, r := range results {
			secs[i] = r.Scans[tool].Duration.Seconds()
		}
		datasets = append(datasets, fmt.Sprintf(
			`{"label":%q,"data":%s,"backgroundColor":%q,"borderRadius":4,"maxBarThickness":60}`,
			tool, jsFloatArray(secs), toolColors[tool]))
	}

	bodies := make([]string, len(results))
	arrowheads := make([]string, len(results))
	for i, r := range results {
		bodies[i] = kingfisherBodyLabel(r, tools)
		arrowheads[i] = kingfisherArrowhead(r, tools)
	}
	bodiesJSON := jsStringArray(bodies)
	arrowheadsJSON := jsStringArray(arrowheads)

	// Subtitle: "lower is better" plus the tool versions used.
	versionParts := make([]string, 0, len(tools))
	for _, t := range tools {
		versionParts = append(versionParts, fmt.Sprintf("%s %s", t, versions[t]))
	}
	subtitleJSON, _ := json.Marshal([]string{
		"Lower is better — shorter bars (↓) win.   Versions: " + strings.Join(versionParts, " · "),
		"Based on results of internal testing conducted by MongoDB engineering",
	})

	return fmt.Sprintf(`{
  type:'bar',
  data:{labels:%s,datasets:[%s]},
  options:{
    layout:{padding:{top:72,bottom:8}},
    plugins:{
      title:{display:true,text:'Runtime comparison',font:{size:30,family:'Georgia, serif'},color:'#16243d',padding:20},
      subtitle:{display:true,position:'bottom',text:%s,color:'#7a7a7a',font:{size:12},padding:{top:18}},
      legend:{position:'top',labels:{boxWidth:18,font:{size:15},color:'#16243d'}},
      datalabels:{
        display:function(ctx){return ctx.datasetIndex===0;},
        clamp:true,textAlign:'center',color:'#16243d',
        labels:{
          value:{
            anchor:'end',align:'end',offset:20,
            font:{weight:'bold',size:11,lineHeight:1.15},
            formatter:function(value,ctx){return %s[ctx.dataIndex];}
          },
          head:{
            anchor:'end',align:'end',offset:-1,
            font:{size:24,lineHeight:1},
            formatter:function(value,ctx){return %s[ctx.dataIndex];}
          }
        }
      }
    },
    scales:{
      x:{title:{display:true,text:'Repository',font:{size:20},color:'#16243d'},grid:{display:false},ticks:{font:{size:14},color:'#16243d'}},
      y:{beginAtZero:true,grace:'32%%',title:{display:true,text:'Runtime in seconds (lower is better)',font:{size:20},color:'#16243d'},ticks:{font:{size:13},color:'#16243d'}}
    }
  }
}`, labelsJSON, strings.Join(datasets, ","), subtitleJSON, bodiesJSON, arrowheadsJSON)
}

// kingfisherSpeedup returns how much faster Kingfisher was than the slowest
// other tool for this repo. ok is false when there's nothing to compare.
func kingfisherSpeedup(r RepoResult, tools []string) (pct float64, ok bool) {
	kf := r.Scans[toolKingfisher].Duration.Seconds()
	slowest := 0.0
	for _, t := range tools {
		if t == toolKingfisher {
			continue
		}
		if s := r.Scans[t].Duration.Seconds(); s > slowest {
			slowest = s
		}
	}
	if slowest <= 0 || kf <= 0 {
		return 0, false
	}
	return (slowest - kf) / slowest * 100, true
}

// kingfisherBodyLabel is the text block shown high above each Kingfisher bar,
// joined to it by an arrow shaft (the large arrowhead is a separate label).
func kingfisherBodyLabel(r RepoResult, tools []string) string {
	pct, ok := kingfisherSpeedup(r, tools)
	switch {
	case !ok:
		return toolKingfisher
	case pct >= 0:
		return fmt.Sprintf("%s\n%.0f%% faster\n \n│\n│\n│", toolKingfisher, pct)
	default:
		return fmt.Sprintf("%s\n%.0f%% slower", toolKingfisher, -pct)
	}
}

// kingfisherArrowhead is the large arrowhead drawn at the top of each Kingfisher
// bar (empty when Kingfisher isn't faster, so no arrow is shown).
func kingfisherArrowhead(r RepoResult, tools []string) string {
	if pct, ok := kingfisherSpeedup(r, tools); ok && pct >= 0 {
		return "▼"
	}
	return ""
}

// regenerateChart rebuilds the runtime chart from a previous run's report,
// writing a fresh runtime-comparison-<timestamp>.png into the same directory.
func regenerateChart(dir string) error {
	results, tools, versions, err := loadResultsFromReport(dir)
	if err != nil {
		return err
	}
	name := "runtime-comparison-" + time.Now().Format("20060102-150405") + ".png"
	outPath := filepath.Join(dir, name)
	if err := renderChartPNG(buildRuntimeChartConfig(results, tools, versions), outPath); err != nil {
		return err
	}
	fmt.Printf("Chart written to %s\n", outPath)
	return nil
}

// loadResultsFromReport reconstructs the data needed for the chart (runtimes,
// tool order, versions) by parsing the comparison_<timestamp>.md report in dir.
func loadResultsFromReport(dir string) ([]RepoResult, []string, map[string]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "comparison_*.md"))
	if err != nil || len(matches) == 0 {
		return nil, nil, nil, fmt.Errorf("no comparison_*.md report found in %s", dir)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		return nil, nil, nil, err
	}
	lines := strings.Split(string(data), "\n")

	// Runtime table: header columns are "<Tool> Runtime"; rows are "<repo> <secs>...".
	rtHeader, rtRows := markdownTable(lines, "## Runtime Comparison")
	if len(rtHeader) < 2 {
		return nil, nil, nil, fmt.Errorf("runtime table not found in %s", matches[0])
	}
	tools := make([]string, 0, len(rtHeader)-1)
	for _, h := range rtHeader[1:] {
		tools = append(tools, strings.TrimSpace(strings.TrimSuffix(h, "Runtime")))
	}
	results := make([]RepoResult, 0, len(rtRows))
	for _, row := range rtRows {
		if len(row) < len(tools)+1 {
			continue
		}
		rr := RepoResult{Repo: row[0], Scans: make(map[string]ScanResult, len(tools))}
		for i, t := range tools {
			secs, _ := strconv.ParseFloat(row[i+1], 64)
			rr.Scans[t] = ScanResult{Duration: time.Duration(secs * float64(time.Second))}
		}
		results = append(results, rr)
	}

	// Versions table (optional).
	versions := make(map[string]string, len(tools))
	if _, vRows := markdownTable(lines, "## Tool Versions"); vRows != nil {
		for _, row := range vRows {
			if len(row) >= 2 {
				versions[row[0]] = row[1]
			}
		}
	}
	return results, tools, versions, nil
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
		"width":            1100,
		"height":           720,
		"format":           "png",
		"backgroundColor":  "white",
		"version":          "4",
		"devicePixelRatio": 2,
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

// jsFloatArray formats floats as a compact JS array literal.
func jsFloatArray(vals []float64) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.FormatFloat(v, 'f', 2, 64)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// jsStringArray formats strings as a JS array literal (JSON-encoded elements,
// which is valid JS and preserves embedded newlines as \n).
func jsStringArray(vals []string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		b, _ := json.Marshal(v)
		parts[i] = string(b)
	}
	return "[" + strings.Join(parts, ",") + "]"
}
