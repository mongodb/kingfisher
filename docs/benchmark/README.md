# Benchmark

A Go-based benchmarking tool that clones a set of repositories, runs security scanning tools (Kingfisher, Trufflehog, Gitleaks, and Detect-Secrets), and reports execution times, scan results, and network request counts. An intercepting HTTP proxy (without TLS decryption) counts network requests made by each tool.

## Features

- **Repository Cloning:** Clones a predefined list of repositories.
- **Tool Execution:** Runs external scanning tools and collects timing and result metrics.
- **Network Request Counting:** Uses an HTTP proxy (listening on 127.0.0.1:9191) to count each network request made.
- **Multi-Format Reporting:** Outputs results as a plain text table (default), Markdown table (`-markdown`), or interactive HTML report (`-html`).
- **Custom Base Directory:** Use a custom directory via the `-basedir` flag; defaults to `os.TempDir()/benchmark` if not specified.
- **HTML Report:** When using `-html`, writes to a timestamped HTML file, uses DataTables for sorting/searching, and automatically opens it in your default browser.

## Prerequisites

- **Go:** [Install Go](https://golang.org/doc/install)
- **Git:** Ensure `git` is installed and in your PATH.
- **Scanning Tools:** The following tools must be installed and available in your PATH:
  - `kingfisher`
  - `trufflehog`
  - `gitleaks`
  - `detect-secrets`

## Installation

Clone the repository and build the program:

```bash
git clone https://github.com/yourusername/benchmark-proxy-scanner.git
cd benchmark-proxy-scanner
go build -o benchmark

## Usage

./