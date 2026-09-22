package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePackageType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    PackageType
		wantErr bool
	}{
		{"empty means not configured", "", "", false},
		{"archive", "archive", PackageTypeArchive, false},
		{"binary is an alias for archive", "binary", PackageTypeArchive, false},
		{"deb", "deb", PackageTypeDeb, false},
		{"debian is an alias for deb", "debian", PackageTypeDeb, false},
		{"rpm", "rpm", PackageTypeRPM, false},
		{"case insensitive", "DEB", PackageTypeDeb, false},
		{"surrounding space is trimmed", "  rpm  ", PackageTypeRPM, false},
		{"unknown value is rejected", "snap", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePackageType(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "must be one of archive, deb, rpm")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPackageTypeFromFileName(t *testing.T) {
	tests := []struct {
		fileName string
		want     PackageType
	}{
		{"slack-desktop-4.36.140-amd64.deb", PackageTypeDeb},
		{"code-1.85.0-1234.el8.x86_64.rpm", PackageTypeRPM},
		{"BAT-V0.24.0-X86_64.DEB", PackageTypeDeb},
		{"bat-v0.24.0-x86_64-linux-gnu.tar.gz", PackageTypeArchive},
		{"btop", PackageTypeArchive},
		{"", PackageTypeArchive},
	}

	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			assert.Equal(t, tt.want, PackageTypeFromFileName(tt.fileName))
		})
	}
}

func TestDownloadArchInfo_ResolvedType(t *testing.T) {
	t.Run("explicit type wins over the file name", func(t *testing.T) {
		got, err := DownloadArchInfo{FileName: "thing-{{.Version}}.tar.gz", Type: "deb"}.ResolvedType()
		require.NoError(t, err)
		assert.Equal(t, PackageTypeDeb, got)
	})

	t.Run("falls back to the file name extension", func(t *testing.T) {
		got, err := DownloadArchInfo{FileName: "example-{{.Version}}.deb"}.ResolvedType()
		require.NoError(t, err)
		assert.Equal(t, PackageTypeDeb, got, "a template placeholder must not hide the extension")

		got, err = DownloadArchInfo{FileName: "example-{{.Version}}.x86_64.rpm"}.ResolvedType()
		require.NoError(t, err)
		assert.Equal(t, PackageTypeRPM, got)

		got, err = DownloadArchInfo{FileName: "example-{{.Version}}.tar.gz"}.ResolvedType()
		require.NoError(t, err)
		assert.Equal(t, PackageTypeArchive, got)
	})

	t.Run("an unknown type is an error", func(t *testing.T) {
		_, err := DownloadArchInfo{FileName: "x.deb", Type: "snap"}.ResolvedType()
		require.Error(t, err)
	})
}

func TestDownloadArchInfo_ShouldInstall(t *testing.T) {
	yes, no := true, false

	tests := []struct {
		name string
		info DownloadArchInfo
		want bool
	}{
		{"explicit install on a deb", DownloadArchInfo{FileName: "example-{{.Version}}.deb", Type: "deb", Install: &yes}, true},
		{"deb defaults to installing", DownloadArchInfo{FileName: "example.deb"}, true},
		{"rpm defaults to installing", DownloadArchInfo{FileName: "example.rpm"}, true},
		{"install false opts out", DownloadArchInfo{FileName: "example.deb", Install: &no}, false},
		{"archives are never package installs", DownloadArchInfo{FileName: "example.tar.gz"}, false},
		{"install true on an archive is ignored", DownloadArchInfo{FileName: "example.tar.gz", Install: &yes}, false},
		{"an unknown type does not install", DownloadArchInfo{FileName: "example.deb", Type: "snap", Install: &yes}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.info.ShouldInstall())
		})
	}
}

func TestResolvedType(t *testing.T) {
	t.Run("uses the resolved install type", func(t *testing.T) {
		b := Binaries{InstallType: "deb", DownloadFileName: "thing.tar.gz"}
		assert.Equal(t, PackageTypeDeb, b.ResolvedType())
	})

	t.Run("falls back to the downloaded file name", func(t *testing.T) {
		assert.Equal(t, PackageTypeDeb, Binaries{DownloadFileName: "thing_1.0_amd64.deb"}.ResolvedType())
		assert.Equal(t, PackageTypeRPM, Binaries{DownloadFileName: "thing-1.0.x86_64.rpm"}.ResolvedType())
	})

	t.Run("defaults to archive", func(t *testing.T) {
		assert.Equal(t, PackageTypeArchive, Binaries{}.ResolvedType())
		assert.Equal(t, PackageTypeArchive, Binaries{DownloadFileName: "x.tar.gz"}.ResolvedType())
	})
}

func TestIsPackageInstall(t *testing.T) {
	assert.True(t, Binaries{InstallType: "deb", InstallPackage: true}.IsPackageInstall())
	assert.False(t, Binaries{InstallType: "deb"}.IsPackageInstall(), "install: false must not package-install")
	assert.False(t, Binaries{}.IsPackageInstall())
}

func TestIsPackage(t *testing.T) {
	assert.True(t, PackageTypeDeb.IsPackage())
	assert.True(t, PackageTypeRPM.IsPackage())
	assert.False(t, PackageTypeArchive.IsPackage())
	assert.False(t, PackageType("").IsPackage())
}

func TestValidateType(t *testing.T) {
	valid := Binaries{
		Name: "example",
		Download: map[string]map[string]DownloadArchInfo{
			"linux": {"amd64": {FileName: "example-{{.Version}}.deb", Type: "deb"}},
		},
	}
	require.NoError(t, valid.ValidateType())
	require.NoError(t, Binaries{Name: "example"}.ValidateType(), "no download block is fine")

	invalid := Binaries{
		Name: "example",
		Download: map[string]map[string]DownloadArchInfo{
			"linux": {"amd64": {FileName: "example.snap", Type: "snap"}},
		},
	}
	err := invalid.ValidateType()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "example")
	assert.Contains(t, err.Error(), "download.linux.amd64")
	assert.Contains(t, err.Error(), "snap")
}
