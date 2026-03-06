package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "iam-advisor",
	Short: "Discover effective AWS IAM permissions from CloudTrail",
	Long: `iam-advisor analyzes AWS CloudTrail logs to discover the effective IAM
permissions used by a principal, and generates a least-privilege IAM policy.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	rootCmd.AddCommand(analyzeCmd)
}
