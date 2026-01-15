# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Build the project
go build -o binstall .

# Run tests
go test ./...

# Run a specific test
go test -run TestFunctionName ./pkg/utils/

# Run tests with verbose output
go test -v ./...

# Run fuzz tests
go test -fuzz=FuzzExtractVersion ./pkg/utils/
```

## Architecture Overview

binstall is a CLI tool that downloads and installs binary releases from GitHub repositories based on YAML configuration files.

### Core Flow

1. **Configuration**: YAML files define binaries to manage, including GitHub URL, files to extract, install location, and version detection commands
2. **Update Check**: Compares local binary version (via configured shell command + regex) against latest GitHub release
3. **Download & Install**: Downloads release asset matching current OS/arch, extracts archive, moves files to install location, verifies installation

### Package Structure

- `cmd/` - Cobra CLI commands
  - `download/` - Main command that checks for updates and installs binaries
  - `schema/` - Generates JSON schema for config file validation
- `models/` - Data structures for binary configuration (`Binaries`, `File`, `ShaInfo`, `OSArch`)
- `pkg/`
  - `net/` - Core logic: version checking via GitHub API, downloading, extraction (using xtractr), file operations
  - `utils/` - Helpers: YAML parsing, GitHub URL expansion, OS/arch detection from filenames, SHA256 calculation, version extraction via regex
  - `fileio/` - YAML file reading with Go 1.23+ iterator pattern

### Key Implementation Details

- Provider detection is URL-based (`github.com` → GitHub provider)
- OS/arch matching parses release asset filenames for keywords (linux/darwin/windows, amd64/arm64/386)
- Version comparison uses `hashicorp/go-version` library
- Archive extraction supports gzip, zip, bzip, 7z, xz via `golift.io/xtractr`
- GitHub token can be provided via `--token` flag or `GITHUB_TOKEN` env var
- Parallel downloads configurable via `--parallel N` flag (default 4)
- `--dry-run` flag shows what would be installed without making changes

### YAML Config File Structure

Key fields in the `File` struct:
- `checkVersion`: marks which file to use for version detection (runs the binary with `versionCommand.args`)
- `sourcePath`: path inside the archive (use when file is nested, e.g., `btop/bin/btop`)
- `fileName`: final name of the binary after installation
- `copyIt`: whether to copy this file to install location
- `renameTo`: optional rename when copying
