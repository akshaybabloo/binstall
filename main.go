package main

import (
	"fmt"
	"os"

	"github.com/akshaybabloo/binstall/cmd"
)

var (
	version = "dev"
	date    = ""
)

func main() {
	rootCmd := cmd.NewRootCmd(version, date)
	err := rootCmd.Execute()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
