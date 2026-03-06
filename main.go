package main

import (
	"os"

	"github.com/nelssec/iam-advisor/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
