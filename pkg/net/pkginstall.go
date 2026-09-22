package net

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/akshaybabloo/binstall/models"
	"github.com/akshaybabloo/binstall/pkg/elevate"
)

// elevator is the shared privilege escalator. It is a package-level value so a
// single password prompt covers every package installed in one run.
var elevator = elevate.New()

// pkgLock serialises package manager invocations. dpkg and rpm both take a
// global database lock, so running two installs concurrently makes one of them
// fail even though the downloads themselves parallelise fine.
var pkgLock sync.Mutex

// packageManager describes one concrete tool that can install a local package
// file, along with how to query and remove what it installed.
type packageManager struct {
	// name is the executable looked up on PATH.
	name string
	// env holds extra "KEY=value" entries the tool needs, e.g. to stop apt
	// from opening an interactive configuration dialog mid-install.
	env []string
	// installArgs builds the argv to install a local package file.
	installArgs func(path string) []string
	// removeArgs builds the argv to remove an installed package by name.
	removeArgs func(pkg string) []string
	// repair, when set, runs after a failed low-level install to pull in
	// dependencies the package file alone could not satisfy.
	repair func() (string, []string, bool)
}

// debManagers lists the tools that can install a .deb, best first. The
// high-level apt-get resolves dependencies from configured repositories;
// dpkg alone cannot, so it is the last resort and is paired with a repair step.
var debManagers = []packageManager{
	{
		name:        "apt-get",
		env:         []string{"DEBIAN_FRONTEND=noninteractive"},
		installArgs: func(path string) []string { return []string{"install", "-y", "--allow-downgrades", path} },
		removeArgs:  func(pkg string) []string { return []string{"remove", "-y", pkg} },
	},
	{
		name:        "dpkg",
		env:         []string{"DEBIAN_FRONTEND=noninteractive"},
		installArgs: func(path string) []string { return []string{"-i", path} },
		removeArgs:  func(pkg string) []string { return []string{"-r", pkg} },
		repair: func() (string, []string, bool) {
			if _, err := exec.LookPath("apt-get"); err != nil {
				return "", nil, false
			}
			return "apt-get", []string{"-f", "install", "-y"}, true
		},
	},
}

// rpmManagers lists the tools that can install a .rpm, best first.
var rpmManagers = []packageManager{
	{
		name:        "dnf",
		installArgs: func(path string) []string { return []string{"install", "-y", "--allowerasing", path} },
		removeArgs:  func(pkg string) []string { return []string{"remove", "-y", pkg} },
	},
	{
		// No --allow-unsigned-rpm: dnf, yum and rpm all verify signatures, and
		// binstall's own checksum check only runs when the config supplies one,
		// so skipping verification here would be the weakest link.
		name:        "zypper",
		installArgs: func(path string) []string { return []string{"--non-interactive", "install", path} },
		removeArgs:  func(pkg string) []string { return []string{"--non-interactive", "remove", pkg} },
	},
	{
		name:        "yum",
		installArgs: func(path string) []string { return []string{"install", "-y", path} },
		removeArgs:  func(pkg string) []string { return []string{"remove", "-y", pkg} },
	},
	{
		name:        "rpm",
		installArgs: func(path string) []string { return []string{"-Uvh", "--replacepkgs", path} },
		removeArgs:  func(pkg string) []string { return []string{"-e", pkg} },
	},
}

// lookPath is swapped out in tests to simulate hosts with different tooling.
var lookPath = exec.LookPath

// managersFor returns the candidate managers for a package type.
func managersFor(t models.PackageType) []packageManager {
	switch t {
	case models.PackageTypeDeb:
		return debManagers
	case models.PackageTypeRPM:
		return rpmManagers
	default:
		return nil
	}
}

// resolvePackageManager picks the first available manager for the type, or
// explains what is missing. The error names the type so a .deb config on a
// Fedora box reports the real problem rather than a bare "not found".
func resolvePackageManager(t models.PackageType) (packageManager, error) {
	candidates := managersFor(t)
	for _, m := range candidates {
		if _, err := lookPath(m.name); err == nil {
			return m, nil
		}
	}

	names := make([]string, 0, len(candidates))
	for _, m := range candidates {
		names = append(names, m.name)
	}
	return packageManager{}, fmt.Errorf("no package manager found to install a %s package (looked for: %s)", t, strings.Join(names, ", "))
}

// PackageManagerName returns the tool that would install b, for display in the
// dry-run summary. It returns an empty string when b is not a package install
// or when no suitable manager exists on this host.
func PackageManagerName(b models.Binaries) string {
	t := b.ResolvedType()
	if !t.IsPackage() || !b.IsPackageInstall() {
		return ""
	}
	m, err := resolvePackageManager(t)
	if err != nil {
		return ""
	}
	return m.name
}

// NeedsRoot reports whether installing or removing b requires root privileges.
func NeedsRoot(b models.Binaries) bool {
	return b.IsPackageInstall()
}

// ResolvedInstallType returns the install type a config resolves to on this
// host, reading the download entry directly so it also works for a binary that
// has not been through the update check.
func ResolvedInstallType(b models.Binaries) models.PackageType {
	resolved, err := resolveInstallSpec(b)
	if err != nil {
		return models.PackageTypeArchive
	}
	return resolved.ResolvedType()
}

// PackageToRemove reports which package an inactive config would uninstall,
// for the --check and --dry-run summaries. An empty name with no error means
// nothing is installed.
func PackageToRemove(b models.Binaries) (string, error) {
	resolved, err := resolveInstallSpec(b)
	if err != nil {
		return "", err
	}
	return packageNameOf(resolved)
}

// NeedsRootForRemoval reports whether uninstalling b requires root. Unlike
// NeedsRoot it reads the config directly, because an inactive binary never goes
// through the update check that resolves the install spec.
func NeedsRootForRemoval(b models.Binaries) bool {
	resolved, err := resolveInstallSpec(b)
	if err != nil {
		return false
	}
	return resolved.IsPackageInstall()
}

// PrepareElevation resolves how to become root, prompting for a password if
// that is the only available route. Call it once, from a point where a prompt
// is acceptable, before any concurrent installs start.
func PrepareElevation() error {
	return elevator.Prepare()
}

// packageNameOf returns the package name to query or remove.
//
// After a download the package file's own metadata is authoritative. Without
// one - which is the case when an inactive config is being uninstalled and
// nothing was fetched - the package manager is asked which package owns the
// binary named in files.
func packageNameOf(b models.Binaries) (string, error) {
	t := b.ResolvedType()
	if !t.IsPackage() {
		return "", fmt.Errorf("%s is not a package install", b.Name)
	}

	if b.DownloadFilePath != "" {
		return packageNameFromFile(t, b.DownloadFilePath)
	}
	return packageNameFromInstalledBinary(b, t)
}

// packageNameFromFile reads the package name out of a downloaded .deb or .rpm.
func packageNameFromFile(t models.PackageType, path string) (string, error) {
	var cmd *exec.Cmd
	switch t {
	case models.PackageTypeDeb:
		cmd = exec.Command("dpkg-deb", "-f", path, "Package")
	case models.PackageTypeRPM:
		cmd = exec.Command("rpm", "-qp", "--nosignature", "--queryformat", "%{NAME}", path)
	default:
		return "", fmt.Errorf("%s is not a package file", path)
	}

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to read package name from %s: %w", path, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// packageNameFromInstalledBinary asks the package manager which package owns
// the binary a config's files entry names.
//
// Only a checkVersion entry is considered. That flag already marks the one
// binary that identifies this config - it is what gets run to read the
// installed version - which makes it the right anchor for working out what to
// uninstall, rather than any incidental file the config happens to list.
//
// An empty name with no error means nothing is installed, so there is nothing
// to remove.
func packageNameFromInstalledBinary(b models.Binaries, t models.PackageType) (string, error) {
	var tried []string

	for _, file := range b.Files {
		if !file.CheckVersion || file.FileName == "" || file.FileName == "*" {
			continue
		}
		tried = append(tried, file.FileName)

		binPath, err := exec.LookPath(file.FileName)
		if err != nil {
			continue
		}

		name, err := packageOwningFile(t, binPath)
		if err != nil {
			logrus.Debugf("Could not find the package owning %s: %v", binPath, err)
			continue
		}
		return name, nil
	}

	if len(tried) == 0 {
		return "", fmt.Errorf("cannot work out which package to remove for %s: deleteIfNotActive on a %s config needs a files entry with checkVersion: true and a fileName naming the installed binary", b.Name, t)
	}

	// The binaries are not on PATH, so the package is already gone.
	logrus.Debugf("None of %v are installed, nothing to remove for %s", tried, b.Name)
	return "", nil
}

// packageOwningFile returns the package that installed path.
func packageOwningFile(t models.PackageType, path string) (string, error) {
	switch t {
	case models.PackageTypeDeb:
		out, err := exec.Command("dpkg", "-S", path).Output()
		if err != nil {
			return "", err
		}
		// Output is "<package>: <path>", or "<package>:<arch>: <path>" on a
		// multiarch system, so take the field before the path and drop any
		// architecture qualifier.
		name, _, found := strings.Cut(strings.TrimSpace(string(out)), ": ")
		if !found {
			return "", fmt.Errorf("unexpected dpkg -S output for %s", path)
		}
		name, _, _ = strings.Cut(name, ":")
		return strings.TrimSpace(name), nil

	case models.PackageTypeRPM:
		out, err := exec.Command("rpm", "-qf", "--queryformat", "%{NAME}", path).Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil

	default:
		return "", fmt.Errorf("%s is not a package type", t)
	}
}

// installedPackageVersion returns the version the package database reports for
// pkg, or an empty string when it is not installed.
func installedPackageVersion(t models.PackageType, pkg string) string {
	var cmd *exec.Cmd
	switch t {
	case models.PackageTypeDeb:
		cmd = exec.Command("dpkg-query", "-W", "-f=${Version}", pkg)
	case models.PackageTypeRPM:
		cmd = exec.Command("rpm", "-q", "--queryformat", "%{VERSION}", pkg)
	default:
		return ""
	}

	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// installPackage installs an already-downloaded .deb or .rpm using the host's
// package manager, escalating privileges as needed.
func installPackage(b models.Binaries) error {
	t := b.ResolvedType()
	m, err := resolvePackageManager(t)
	if err != nil {
		return err
	}

	// Serialised because the underlying package databases are single-writer.
	pkgLock.Lock()
	defer pkgLock.Unlock()

	logrus.Debugf("Installing %s with %s", b.DownloadFilePath, m.name)
	out, err := elevator.RunWithEnv(m.env, m.name, m.installArgs(b.DownloadFilePath)...)
	if err != nil {
		if repairName, repairArgs, ok := repairFor(m); ok {
			logrus.Debugf("Install with %s failed, attempting dependency repair with %s", m.name, repairName)
			if repairOut, repairErr := elevator.RunWithEnv(m.env, repairName, repairArgs...); repairErr == nil {
				logrus.Debugf("Dependency repair output: %s", strings.TrimSpace(string(repairOut)))
				return nil
			}
		}
		return fmt.Errorf("failed to install %s package for %s: %w\nOutput: %s", t, b.Name, err, strings.TrimSpace(string(out)))
	}

	logrus.Debugf("%s output: %s", m.name, strings.TrimSpace(string(out)))
	return nil
}

// repairFor returns the manager's dependency repair command, if it has one.
func repairFor(m packageManager) (string, []string, bool) {
	if m.repair == nil {
		return "", nil, false
	}
	return m.repair()
}

// removePackage uninstalls the package a config installed. It is used when a
// config is marked inactive with settings.deleteIfNotActive.
func removePackage(b models.Binaries) error {
	t := b.ResolvedType()
	m, err := resolvePackageManager(t)
	if err != nil {
		return err
	}

	pkg, err := packageNameOf(b)
	if err != nil {
		return err
	}

	// Nothing to do if the package was never installed, which keeps repeated
	// runs with deleteIfNotActive quiet instead of failing on the second one.
	if pkg == "" || installedPackageVersion(t, pkg) == "" {
		logrus.Debugf("Package %s is not installed, nothing to remove", pkg)
		return nil
	}

	pkgLock.Lock()
	defer pkgLock.Unlock()

	out, err := elevator.RunWithEnv(m.env, m.name, m.removeArgs(pkg)...)
	if err != nil {
		return fmt.Errorf("failed to remove %s package %s: %w\nOutput: %s", t, pkg, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// verifyPackageInstall checks that a package install produced a working binary
// at the expected version.
//
// Unlike an archive install, the package manager decides where files land, so
// the binary is located on PATH rather than under InstallLocation.
func verifyPackageInstall(b models.Binaries) error {
	checked := false

	for _, file := range b.Files {
		if !file.CheckVersion {
			continue
		}
		checked = true

		fullPath, err := exec.LookPath(file.FileName)
		if err != nil {
			return fmt.Errorf("%s was installed but %s is not on PATH: %w", b.Name, file.FileName, err)
		}

		stdout, err := exec.Command(fullPath, file.VersionCommand.Args).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to execute %s: %w\nOutput: %s", fullPath, err, stdout)
		}

		if err := compareInstalledVersion(file.FileName, string(stdout), file.VersionCommand.RegexVersion, b.NewVersion); err != nil {
			return err
		}
	}

	// With no checkVersion file to run, fall back to the package database so a
	// silent no-op install still gets caught.
	if !checked {
		pkg, err := packageNameOf(b)
		if err != nil {
			return err
		}
		if installedPackageVersion(b.ResolvedType(), pkg) == "" {
			return fmt.Errorf("package %s does not appear to be installed after installing %s", pkg, b.Name)
		}
	}

	return nil
}
