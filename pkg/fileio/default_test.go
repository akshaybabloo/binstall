package fileio

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/akshaybabloo/binstall/models"
)

func writeYaml(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
}

func collect(t *testing.T, dir string) ([]models.Binaries, []error) {
	t.Helper()
	seq, err := ReadYamlFiles(dir)
	require.NoError(t, err)

	var bins []models.Binaries
	var errs []error
	for b, e := range seq {
		bins = append(bins, b)
		errs = append(errs, e)
	}
	return bins, errs
}

func TestReadYamlFiles(t *testing.T) {
	t.Run("valid_yaml_files", func(t *testing.T) {
		dir := t.TempDir()
		writeYaml(t, dir, "a.yaml", "name: alpha")
		writeYaml(t, dir, "b.yaml", "name: bravo")

		bins, errs := collect(t, dir)
		require.Len(t, bins, 2)
		require.Len(t, errs, 2)

		// Glob is sorted, so a.yaml comes before b.yaml.
		assert.NoError(t, errs[0])
		assert.NoError(t, errs[1])
		assert.Equal(t, "alpha", bins[0].Name)
		assert.Equal(t, "bravo", bins[1].Name)
	})

	t.Run("invalid_yaml_yields_error", func(t *testing.T) {
		dir := t.TempDir()
		writeYaml(t, dir, "bad.yaml", ": : :")

		bins, errs := collect(t, dir)
		require.Len(t, bins, 1)
		require.Len(t, errs, 1)

		assert.Error(t, errs[0])
		assert.Equal(t, models.Binaries{}, bins[0])
	})

	t.Run("mixed_valid_and_invalid", func(t *testing.T) {
		dir := t.TempDir()
		writeYaml(t, dir, "a-good.yaml", "name: alpha")
		writeYaml(t, dir, "b-bad.yaml", ": : :")
		writeYaml(t, dir, "c-good.yaml", "name: charlie")

		bins, errs := collect(t, dir)
		require.Len(t, bins, 3)

		assert.NoError(t, errs[0])
		assert.Equal(t, "alpha", bins[0].Name)
		assert.Error(t, errs[1])
		assert.Equal(t, models.Binaries{}, bins[1])
		assert.NoError(t, errs[2])
		assert.Equal(t, "charlie", bins[2].Name)
	})

	t.Run("non_yaml_extensions_ignored", func(t *testing.T) {
		dir := t.TempDir()
		// Glob is *.yaml only — .yml, .json, .txt are all skipped.
		require.NoError(t, os.WriteFile(filepath.Join(dir, "a.yml"), []byte("name: alpha"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"name":"bravo"}`), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "c.txt"), []byte("name: charlie"), 0o644))

		bins, _ := collect(t, dir)
		assert.Empty(t, bins)
	})

	t.Run("empty_directory", func(t *testing.T) {
		bins, errs := collect(t, t.TempDir())
		assert.Empty(t, bins)
		assert.Empty(t, errs)
	})

	t.Run("nonexistent_directory", func(t *testing.T) {
		// filepath.Glob returns an empty slice (not an error) for a missing dir,
		// so the iterator yields nothing.
		bins, errs := collect(t, filepath.Join(t.TempDir(), "does-not-exist"))
		assert.Empty(t, bins)
		assert.Empty(t, errs)
	})

	t.Run("early_break_stops_iteration", func(t *testing.T) {
		dir := t.TempDir()
		writeYaml(t, dir, "a.yaml", "name: alpha")
		writeYaml(t, dir, "b.yaml", "name: bravo")
		writeYaml(t, dir, "c.yaml", "name: charlie")

		seq, err := ReadYamlFiles(dir)
		require.NoError(t, err)

		count := 0
		for range seq {
			count++
			break
		}
		assert.Equal(t, 1, count)
	})

	t.Run("early_break_after_error", func(t *testing.T) {
		dir := t.TempDir()
		writeYaml(t, dir, "a-bad.yaml", ": : :")
		writeYaml(t, dir, "b-good.yaml", "name: bravo")

		seq, err := ReadYamlFiles(dir)
		require.NoError(t, err)

		count := 0
		for _, e := range seq {
			count++
			require.Error(t, e)
			break
		}
		assert.Equal(t, 1, count)
	})
}
