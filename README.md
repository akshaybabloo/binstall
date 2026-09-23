# Binary Installer

A binary updater based on YAML configuration

## Installation

Choose your platform and download the binary from the [releases page](https://github.com/akshaybabloo/binstall/releases).

## Usage

> [!CAUTION]
> As of latest release, `binstall` will always install the latest binary from the configuration file.

```bash
binstall download <config-directory>/
```

An example of the configuration can be found [here](https://github.com/akshaybabloo/dotfiles/tree/main/binary_configs).

## Installing `.deb` and `.rpm` packages

binstall can hand a release asset to the system package manager instead of extracting it. You name the file to download, and `type` and `install` on that download entry say what to do with it:

```yaml
name: example
url: https://github.com/example/example
download:
  linux:
    amd64:
      fileName: "example-{{.Version}}.deb"
      type: deb          # archive (default) | deb | rpm
      install: true
```

`type` is optional: when it is omitted the extension of `fileName` decides, so `example-{{.Version}}.deb` installs as a deb without saying so. Set `type` explicitly when the extension does not match the format, for example a `.bin` file that is really a package. `install` is also optional and defaults to `true` for deb and rpm; `install: false` downloads the file without installing it.

Packages are only ever installed from an explicit `download` entry. Release asset auto-detection still skips `.deb` and `.rpm`, so configs without a `download` block keep installing the archive exactly as before.

### Checking the installed version

`files` is optional for a package install. When present it works exactly as it does for archives - a `checkVersion` entry runs the binary and matches its output against `regexVersion` - which is how binstall decides whether an update is needed and confirms the install afterwards. Because the package manager decides where files land, the binary is looked up on `PATH` rather than under `installLocation`:

```yaml
files:
  - fileName: "example"
    copyIt: false
    checkVersion: true
    versionCommand:
      args: "--version"
      regexVersion: "\\d+\\.\\d+\\.\\d+"
```

With no `files` block there is nothing to read a current version from, so the package is reinstalled on every run.

`installLocation` and the `copyIt` / `sourcePath` / `renameTo` fields are not used for a package install.

### Package manager selection

| type  | tried in order                      |
|-------|-------------------------------------|
| `deb` | `apt-get`, then `dpkg`              |
| `rpm` | `dnf`, `zypper`, `yum`, then `rpm`  |

The high-level tools come first because they resolve dependencies from the configured repositories. A `dpkg -i` fallback is followed by `apt-get -f install -y` to pull in anything the package file alone could not satisfy.

### Privileges

Package installs need root. binstall works out how to get it once per run, before any downloads start, so a run installing several packages asks at most once:

1. Already running as root - the command runs directly.
2. `sudo -n` works (a `NOPASSWD` rule or a warm sudo timestamp).
3. `sudo` is available and stdin is a terminal - the password is read once without echo and piped to `sudo -S`.
4. `pkexec` is available - polkit prompts instead, which is what makes this work from a desktop session with no controlling terminal.

If none apply, the run stops with an explanation rather than blocking on a prompt nobody can see. Package installs are serialised even with `--parallel`, because dpkg and rpm each take a global database lock; downloads still run concurrently.

`--check` and `--dry-run` never install, uninstall or prompt; the dry run reports the package manager it would use.

### Removing a package

`settings.deleteIfNotActive` uninstalls through the package manager instead of deleting `installLocation`:

```yaml
name: example
url: https://github.com/example/example
download:
  linux:
    amd64:
      fileName: "example-{{.Version}}.deb"
      type: deb
      install: true
files:
  - fileName: "example"
    copyIt: false
    checkVersion: true
settings:
  active: false
  deleteIfNotActive: true
```

Nothing is downloaded on a removal-only run, so the package name cannot come from the package file. binstall asks the package manager which package owns the installed binary instead (`dpkg -S` or `rpm -qf`), using the `files` entry marked `checkVersion: true` - the same entry that identifies the binary for version checks. So removing a package config needs a `files` entry with both `checkVersion: true` and a `fileName`, even though `files` is otherwise optional for a package install.

Removing a package that is not installed is a no-op, so repeated runs are safe and do not prompt for a password.

> [!NOTE]
> `{{.Version}}` renders the release tag verbatim, including any leading `v`. For a project tagged `v1.2.3` that names its package `example_1.2.3_amd64.deb`, write the file name without the template or the lookup will not match.
