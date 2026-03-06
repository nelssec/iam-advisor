package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/nelssec/iam-advisor/internal/cloudtrail"
	"github.com/nelssec/iam-advisor/internal/policy"
	"github.com/spf13/cobra"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/aws"
)

var (
	flagPrincipal string
	flagService   string
	flagDays      int
	flagAccount   string
	flagOrg       bool
	flagOutput    string
	flagRoleName  string
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze CloudTrail events to discover effective IAM permissions",
	RunE:  runAnalyze,
}

func init() {
	analyzeCmd.Flags().StringVar(&flagPrincipal, "principal", "", "IAM principal ARN to analyze (e.g. arn:aws:iam::123456789012:role/MyRole)")
	analyzeCmd.Flags().StringVar(&flagService, "service", "", "AWS service to filter (e.g. s3, ec2). Empty means all services")
	analyzeCmd.Flags().IntVar(&flagDays, "days", 30, "Number of days of CloudTrail history to analyze")
	analyzeCmd.Flags().StringVar(&flagAccount, "account", "", "AWS account ID to analyze (defaults to current account)")
	analyzeCmd.Flags().BoolVar(&flagOrg, "org", false, "Iterate all accounts in the AWS Organization")
	analyzeCmd.Flags().StringVar(&flagOutput, "output", "text", "Output format: json or text")
	analyzeCmd.Flags().StringVar(&flagRoleName, "role-name", "OrganizationAccountAccessRole", "IAM role name to assume in each org account")
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("loading AWS config: %w", err)
	}

	var accounts []string

	if flagOrg {
		slog.Info("discovering organization accounts")
		orgAccounts, err := listOrgAccounts(ctx, cfg)
		if err != nil {
			return fmt.Errorf("listing org accounts: %w", err)
		}
		accounts = orgAccounts
		slog.Info("discovered org accounts", "count", len(accounts))
	} else if flagAccount != "" {
		accounts = []string{flagAccount}
	} else {
		// Use current account
		stsClient := sts.NewFromConfig(cfg)
		identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return fmt.Errorf("getting caller identity: %w", err)
		}
		accounts = []string{aws.ToString(identity.Account)}
		slog.Info("using current account", "account", accounts[0])
	}

	allEvents := make(cloudtrail.EventCollection)

	for _, accountID := range accounts {
		slog.Info("analyzing account", "account", accountID)

		accountCfg := cfg
		if flagOrg {
			assumedCfg, err := assumeRoleConfig(ctx, cfg, accountID, flagRoleName)
			if err != nil {
				slog.Error("failed to assume role in account, skipping", "account", accountID, "error", err)
				continue
			}
			accountCfg = assumedCfg
		}

		collector := cloudtrail.NewCollector(accountCfg)
		events, err := collector.Collect(ctx, cloudtrail.CollectOptions{
			Principal: flagPrincipal,
			Service:   flagService,
			Days:      flagDays,
		})
		if err != nil {
			slog.Error("failed to collect events for account", "account", accountID, "error", err)
			continue
		}

		slog.Info("collected events", "account", accountID, "count", len(events))
		allEvents.Merge(events)
	}

	slog.Info("generating least-privilege policy", "unique_actions", allEvents.ActionCount())

	pol := policy.Generate(allEvents)

	switch flagOutput {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(pol); err != nil {
			return fmt.Errorf("encoding policy: %w", err)
		}
	case "text":
		printTextOutput(pol)
	default:
		return fmt.Errorf("unknown output format %q, use json or text", flagOutput)
	}

	return nil
}

func listOrgAccounts(ctx context.Context, cfg aws.Config) ([]string, error) {
	orgClient := organizations.NewFromConfig(cfg)

	var accountIDs []string
	paginator := organizations.NewListAccountsPaginator(orgClient, &organizations.ListAccountsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing org accounts page: %w", err)
		}
		for _, acct := range page.Accounts {
			accountIDs = append(accountIDs, aws.ToString(acct.Id))
		}
	}
	return accountIDs, nil
}

func assumeRoleConfig(ctx context.Context, baseCfg aws.Config, accountID, roleName string) (aws.Config, error) {
	roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)
	slog.Info("assuming role", "role_arn", roleARN)

	stsClient := sts.NewFromConfig(baseCfg)
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN)

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithCredentialsProvider(provider),
		config.WithRegion(baseCfg.Region),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("loading config with assumed role %s: %w", roleARN, err)
	}
	return cfg, nil
}

func printTextOutput(pol policy.Document) {
	fmt.Printf("Least-Privilege IAM Policy\n")
	fmt.Printf("==========================\n\n")
	fmt.Printf("Version: %s\n\n", pol.Version)
	for i, stmt := range pol.Statement {
		fmt.Printf("Statement %d:\n", i+1)
		fmt.Printf("  Effect:    %s\n", stmt.Effect)
		fmt.Printf("  Actions:   %v\n", stmt.Action)
		fmt.Printf("  Resources: %v\n\n", stmt.Resource)
	}
}
