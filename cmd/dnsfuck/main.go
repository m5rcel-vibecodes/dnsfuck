package main

import (
	"os"

	"github.com/m5rcel-vibecodes/dnsfuck/pkg/cli"
)

func main() {
	rootCmd := cli.NewRootCmd()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
