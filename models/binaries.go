package models

import (
	"fmt"
	"path/filepath"
	"strings"
)

// VersionCommand holds the information about the version command that can be used to get the version of the binary
type VersionCommand struct {
	Args         string `yaml:"args,omitempty" json:"args,omitempty"`
	RegexVersion string `yaml:"regexVersion,omitempty" json:"regexVersion,omitempty"`
}

// Settings holds the per-binary activation state read from the config's "settings" block.
type Settings struct {
	Active            bool `yaml:"active,omitempty" json:"active,omitempty"`
	DeleteIfNotActive bool `yaml:"deleteIfNotActive,omitempty" json:"deleteIfNotActive,omitempty"`
}

// UnmarshalYAML defaults Active to true when the settings block omits it, so a
// config stays enabled unless active is explicitly set to false.
func (s *Settings) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawSettings struct {
		Active            *bool `yaml:"active,omitempty"`
		DeleteIfNotActive bool  `yaml:"deleteIfNotActive,omitempty"`
	}
	var raw rawSettings
	if err := unmarshal(&raw); err != nil {
		return err
	}
	if raw.Active == nil {
		s.Active = true
	} else {
		s.Active = *raw.Active
	}
	s.DeleteIfNotActive = raw.DeleteIfNotActive
	return nil
}

// File holds the information about the binary files
type File struct {
	CheckVersion       bool           `yaml:"checkVersion,omitempty" json:"checkVersion"`
	FileName           string         `yaml:"fileName,omitempty" json:"fileName"`
	CopyContentsFrom   string         `yaml:"copyContentsFrom,omitempty" json:"copyContentsFrom,omitempty"`
	SourcePath         string         `yaml:"sourcePath,omitempty" json:"sourcePath,omitempty"` // Path inside archive (if different from fileName)
	Exists             bool           `yaml:"exists,omitempty" json:"exists,omitempty"`
	CopyIt             bool           `yaml:"copyIt" json:"copyIt"`                         // Copy the binary to the install location
	RenameTo           string         `yaml:"renameTo,omitempty" json:"renameTo,omitempty"` // Rename the binary to this name
	ExecuteWhenCopying bool           `yaml:"executeWhenCopying,omitempty" json:"executeWhenCopying,omitempty"`
	VersionCommand     VersionCommand `yaml:"versionCommand,omitempty" json:"versionCommand,omitempty"`
}

// DownloadArchInfo holds the download file name for a specific OS/arch combination.
// The FileName field supports Go text/template syntax, e.g. "bat-{{.Version}}-x86_64-unknown-linux-gnu.tar.gz"
type DownloadArchInfo struct {
	FileName string `yaml:"fileName,omitempty" json:"fileName,omitempty"`

	// Type is how this file is installed: "archive" (default), "deb" or
	// "rpm". When empty it is inferred from FileName's extension.
	Type string `yaml:"type,omitempty" json:"type,omitempty" jsonschema:"enum=archive,enum=deb,enum=rpm,description=How this file is installed. Inferred from the file name extension when omitted."`

	// Install hands the file to the system package manager. It defaults to
	// true for deb and rpm, and setting it to false downloads the file
	// without installing it.
	Install *bool `yaml:"install,omitempty" json:"install,omitempty" jsonschema:"description=Install through the system package manager. Defaults to true for deb and rpm."`
}

// ResolvedType returns the entry's configured type, falling back to the
// extension of its file name. A template placeholder in the file name does not
// affect the extension, so this works before the version is known.
func (d DownloadArchInfo) ResolvedType() (PackageType, error) {
	t, err := ParsePackageType(d.Type)
	if err != nil {
		return "", err
	}
	if t != "" {
		return t, nil
	}
	return PackageTypeFromFileName(d.FileName), nil
}

// ShouldInstall reports whether this entry is handed to the system package
// manager. It defaults to true for deb and rpm, since there is nothing else to
// do with such a file, and "install: false" turns it off.
func (d DownloadArchInfo) ShouldInstall() bool {
	t, err := d.ResolvedType()
	if err != nil || !t.IsPackage() {
		return false
	}
	if d.Install == nil {
		return true
	}
	return *d.Install
}

// ShaInfo holds the information about the SHA checksum
// If a binary has a pre-existing checksum, it will be used
// to verify the downloaded binary using the ShaInfo.url
type ShaInfo struct {
	// URL is the URL to the checksum file, if found
	URL string `yaml:"url,omitempty" json:"url,omitempty"`

	// ShaType is the type of the checksum - default should be sha256
	ShaType string `yaml:"shaType,omitempty" json:"shaType,omitempty"`

	// Checksum is calculated if the URL is not found
	Checksum string `yaml:"checksum,omitempty" json:"checksum,omitempty"`
}

// OSArch holds the information about the OS and Arch
type OSArch struct {
	// OS is the operating system
	OS string `yaml:"os,omitempty" json:"os,omitempty"`

	// Arch is the architecture
	Arch string `yaml:"arch,omitempty" json:"arch,omitempty"`
}

// Binaries holds the information about the binaries
type Binaries struct {
	Name string `yaml:"name,omitempty" json:"name"`
	URL  string `yaml:"url,omitempty" json:"url"`

	Download         map[string]map[string]DownloadArchInfo `yaml:"download,omitempty" json:"download,omitempty"`
	Files            []File                                 `yaml:"files,omitempty" json:"files,omitempty"`
	Sha              ShaInfo                                `yaml:"sha,omitempty" json:"sha,omitempty"`
	UpdatesAvailable bool                                   `yaml:"updatesAvailable,omitempty" json:"updatesAvailable,omitempty"`
	Description      string                                 `yaml:"description,omitempty" json:"description,omitempty"`
	Provider         int                                    `yaml:"provider,omitempty" json:"provider,omitempty"`
	OsInfo           OSArch                                 `yaml:"osInfo,omitempty" json:"osInfo,omitempty"`
	DownloadURL      string                                 `yaml:"downloadURL,omitempty" json:"downloadURL,omitempty"`
	DownloadFileName string                                 `yaml:"downloadFileName,omitempty" json:"downloadFileName,omitempty"`
	ContentType      string                                 `yaml:"contentType,omitempty" json:"contentType,omitempty"`
	DownloadFolder   string                                 `yaml:"downloadFolder,omitempty" json:"downloadFolder,omitempty"`
	DownloadFilePath string                                 `yaml:"downloadPath,omitempty" json:"downloadPath,omitempty"`
	InstallLocation  string                                 `yaml:"installLocation,omitempty" json:"installLocation,omitempty"`
	CurrentVersion   string                                 `yaml:"currentVersion,omitempty" json:"currentVersion,omitempty"`
	NewVersion       string                                 `yaml:"newVersion,omitempty" json:"newVersion,omitempty"`

	// InstallType and InstallPackage are resolved during the update check from
	// the download entry matching this host, not read from the config.
	InstallType    string `yaml:"-" json:"-"`
	InstallPackage bool   `yaml:"-" json:"-"`

	// Ignore if the binary should be ignored
	Ignore bool `yaml:"ignore,omitempty" json:"ignore,omitempty"`
	// Shell is the shell command to run the binary, if any
	Shell string `yaml:"shell,omitempty" json:"shell,omitempty"`
	// Token is the token to be used for the download authentication
	Token string `yaml:"_" json:"_"`
	// Settings controls whether this config is active and what happens to installed files when it is not
	Settings *Settings `yaml:"settings,omitempty" json:"settings,omitempty"`
}

// PackageType identifies how a downloaded asset is turned into an installation.
type PackageType string

const (
	// PackageTypeArchive is the default: the asset is an archive (or a bare
	// binary) whose contents are extracted and copied to InstallLocation.
	PackageTypeArchive PackageType = "archive"

	// PackageTypeDeb is a Debian package installed with apt-get/dpkg.
	PackageTypeDeb PackageType = "deb"

	// PackageTypeRPM is an RPM package installed with dnf/zypper/yum/rpm.
	PackageTypeRPM PackageType = "rpm"
)

// IsPackage reports whether the type is a system package handled by a package
// manager rather than an archive extracted into InstallLocation.
func (p PackageType) IsPackage() bool {
	return p == PackageTypeDeb || p == PackageTypeRPM
}

// ParsePackageType normalizes a configured type string. An empty string means
// "not configured" and returns an empty PackageType so the caller can fall back
// to the download file name.
func ParsePackageType(s string) (PackageType, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return "", nil
	case "archive", "binary":
		return PackageTypeArchive, nil
	case "deb", "debian":
		return PackageTypeDeb, nil
	case "rpm":
		return PackageTypeRPM, nil
	default:
		return "", fmt.Errorf("unknown type %q: must be one of archive, deb, rpm", s)
	}
}

// PackageTypeFromFileName infers the package type from a file name's extension,
// used when a config does not set type explicitly.
func PackageTypeFromFileName(fileName string) PackageType {
	switch strings.ToLower(filepath.Ext(fileName)) {
	case ".deb":
		return PackageTypeDeb
	case ".rpm":
		return PackageTypeRPM
	default:
		return PackageTypeArchive
	}
}

// ResolvedType returns the install type worked out for this host: the type
// from the matching download entry, or the extension of the file that was
// actually downloaded, and finally PackageTypeArchive.
func (b Binaries) ResolvedType() PackageType {
	if t, err := ParsePackageType(b.InstallType); err == nil && t != "" {
		return t
	}
	if b.DownloadFileName != "" {
		return PackageTypeFromFileName(b.DownloadFileName)
	}
	return PackageTypeArchive
}

// IsPackageInstall reports whether this binary installs through the system
// package manager rather than by extracting an archive into InstallLocation.
func (b Binaries) IsPackageInstall() bool {
	return b.InstallPackage
}

// ValidateType returns an error if any download entry sets an unrecognized
// type, so a typo is reported against the config rather than silently treated
// as an archive.
func (b Binaries) ValidateType() error {
	for osName, archMap := range b.Download {
		for archName, info := range archMap {
			if _, err := ParsePackageType(info.Type); err != nil {
				return fmt.Errorf("%s: download.%s.%s: %w", b.Name, osName, archName, err)
			}
		}
	}
	return nil
}
