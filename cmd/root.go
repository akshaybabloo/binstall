package cmd

import (
	"fmt"

	"github.com/akshaybabloo/binstall/cmd/download"
	"github.com/akshaybabloo/binstall/cmd/schema"
	"github.com/spf13/cobra"
)

// NewRootCmd root command
func NewRootCmd(appVersion, buildDate string) *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "binstall [OPTIONS] [COMMANDS]",
		Short: "Tool to delete 'node_modules'",
		Long:  `binstall can be used to delete 'node_modules' recursively from sub-folders`,
	}

	rootCmd.AddCommand(download.NewDownloadCmd())
	rootCmd.AddCommand(schema.NewSchemaCmd())

	formattedVersion := format(appVersion, buildDate)
	rootCmd.SetVersionTemplate(formattedVersion)
	rootCmd.Version = formattedVersion

	rootCmd.CompletionOptions.DisableDefaultCmd = true

	return rootCmd
}

func format(version, buildDate string) string {
	return fmt.Sprintf("binstall %s %s\n", version, buildDate)
}
