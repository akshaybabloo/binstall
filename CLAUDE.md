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
    - `pkginstall.go` - deb/rpm installs: package manager selection, install/remove, post-install verification
  - `utils/` - Helpers: YAML parsing, GitHub URL expansion, OS/arch detection from filenames, SHA256 calculation, version extraction via regex
  - `elevate/` - Privilege escalation for package installs (root -> sudo -n -> sudo -S -> pkexec)
  - `fileio/` - YAML file reading with Go 1.23+ iterator pattern

### Key Implementation Details

- Provider detection is URL-based (`github.com` → GitHub provider)
- OS/arch matching parses release asset filenames for keywords (linux/darwin/windows, amd64/arm64/386)
- Version comparison uses `hashicorp/go-version` library
- Archive extraction supports gzip, zip, bzip, 7z, xz via `golift.io/xtractr`
- GitHub token can be provided via `--token` flag or `GITHUB_TOKEN` env var
- Parallel downloads configurable via `--parallel N` flag (default 4)
- `--dry-run` flag shows what would be installed without making changes
- Install type is `archive` (default), `deb` or `rpm`, set per OS/arch by `download.<os>.<arch>.type` and otherwise inferred from that entry's `fileName` extension; `install` (default true for deb/rpm) decides whether the file is handed to the package manager
- `net.resolveInstallSpec` reads that entry and populates the runtime-only `Binaries.InstallType` / `InstallPackage` fields; it deliberately works without a release version, since only the extension matters, which is what lets an inactive config be uninstalled without contacting the provider
- Packages only come from an explicit `download` entry. Release asset auto-detection still skips `.deb`/`.rpm` via `ignoreFileExt`, so configs without a `download` block are unaffected
- Package installs bypass extraction and `moveFiles` entirely; the package manager owns file placement, so verification looks the binary up on `PATH` instead of under `installLocation`
- Root is acquired once per run in `cmd/download` before the worker pool starts, so a password prompt never lands behind the spinner; package manager calls are serialised via `pkgLock` because dpkg/rpm take a global database lock

### YAML Config File Structure

Key fields in the `File` struct:
- `checkVersion`: marks which file to use for version detection (runs the binary with `versionCommand.args`)
- `sourcePath`: path inside the archive (use when file is nested, e.g., `btop/bin/btop`)
- `fileName`: final name of the binary after installation
- `copyIt`: whether to copy this file to install location
- `renameTo`: optional rename when copying

Fields in the `download.<os>.<arch>` entry:
- `fileName`: exact asset name, supports `{{.Version}}` (the release tag, verbatim)
- `type`: `archive` (default), `deb` or `rpm`; inferred from `fileName`'s extension when omitted
- `install`: hand the file to the package manager; defaults to true for deb/rpm

`files` is optional for a deb/rpm config. When present, a `checkVersion` entry drives update detection and post-install verification as usual, but the binary is resolved via `exec.LookPath` rather than `installLocation`.

The package name is never configured. On install it is read from the downloaded file (`dpkg-deb -f` / `rpm -qp`); on removal, where nothing is downloaded, `packageOwningFile` asks `dpkg -S` / `rpm -qf` which package owns the installed binary. The anchor is the `files` entry with `checkVersion: true` (the same one that identifies the binary for version checks), so `deleteIfNotActive` on a package config requires such an entry. An empty name with no error means nothing is installed, which keeps repeat removals quiet.

`cmd/download.removeInactive` resolves every package name before calling `PrepareElevation`, so a misconfigured entry fails without first prompting for a password, and a run whose packages are already gone never prompts at all.
