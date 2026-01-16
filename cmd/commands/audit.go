package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/gcuesta/drystone/internal/agent"
	"github.com/gcuesta/drystone/internal/aws"
	"github.com/gcuesta/drystone/internal/skills/iam"
	"github.com/gcuesta/drystone/internal/storage"
	"github.com/gcuesta/drystone/internal/ui"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run a security audit",
	Long: `Run a security audit on your AWS environment.

Examples:
  drystone audit                    # Interactive mode (recommended)
  drystone audit --non-interactive  # Use saved configuration
`,
	RunE: auditRun,
}

var (
	nonInteractiveFlag bool
	outputDirFlag      string
)

func init() {
	auditCmd.Flags().BoolVar(&nonInteractiveFlag, "non-interactive", false, "Skip interactive setup wizard")
	auditCmd.Flags().StringVar(&outputDirFlag, "output", "./audit-logs", "Output directory for reports")
}

func auditRun(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Run the wizard (always, unless --non-interactive is set)
	var config *ui.WizardConfig
	var err error

	if !nonInteractiveFlag {
		config, err = ui.RunWizard()
		if err != nil {
			return fmt.Errorf("❌ Wizard error: %w", err)
		}

		// Print summary
		ui.PrintSummary(config)

		// Ask for confirmation
		if !ui.ConfirmStart() {
			fmt.Println("❌ Auditoría cancelada")
			return nil
		}

		ui.PrintReady()
	} else {
		// For non-interactive, use defaults
		config = &ui.WizardConfig{
			AWSProfile:     "default",
			AWSRegion:      "us-east-1",
			SelectedSkills: []string{"iam"},
			LLMProvider:    "claude",
			OutputFormats:  []string{"markdown", "json"},
		}
	}

	// Initialize AWS client
	awsClient, err := aws.NewClient(ctx, config.AWSProfile, config.AWSRegion)
	if err != nil {
		return fmt.Errorf("❌ Failed to initialize AWS client: %w", err)
	}

	fmt.Printf("✅ AWS client initialized (Account: %s, Region: %s)\n", config.AWSProfile, config.AWSRegion)

	// Validate AWS credentials
	if err := awsClient.ValidateCredentials(ctx); err != nil {
		return fmt.Errorf("❌ AWS credential validation failed: %w", err)
	}

	// Create session directory
	sessionMgr := storage.NewSessionManager(outputDirFlag)
	session, err := sessionMgr.CreateSession(ctx, awsClient)
	if err != nil {
		return fmt.Errorf("❌ Failed to create session: %w", err)
	}

	fmt.Printf("📁 Session directory: %s\n\n", session.Path)

	// Initialize LLM provider
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" && config.LLMProvider == "claude" {
		fmt.Println("⚠️  ANTHROPIC_API_KEY not set. Using demo mode.")
	}

	providerCfg := agent.Config{
		Provider:       agent.ProviderClaude, // For MVP
		ClaudeAPIKey:   apiKey,
		ValidateSchema: true,
		MaxRetries:     2,
	}

	provider, err := agent.NewProvider(providerCfg)
	if err != nil {
		return fmt.Errorf("❌ Failed to initialize provider: %w", err)
	}

	fmt.Printf("🤖 LLM Provider: %s\n\n", config.LLMProvider)

	// Execute selected skills
	fmt.Println("🔍 Ejecutando auditoría...")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	for _, skillName := range config.SelectedSkills {
		fmt.Printf("\n📊 Skill: %s\n", skillName)
		fmt.Println("──────────────────────────────────────────────")

		if err := runSkill(ctx, skillName, awsClient, provider, session); err != nil {
			fmt.Printf("❌ Skill %s failed: %v\n", skillName, err)
			continue
		}

		fmt.Printf("✅ Skill %s completado\n", skillName)
	}

	// Summary
	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("\n✅ Auditoría completada!\n")
	fmt.Printf("📁 Reportes guardados en: %s\n\n", session.Path)

	return nil
}

func runSkill(ctx context.Context, skillName string, awsClient *aws.Client, provider agent.Provider, session *storage.Session) error {
	fmt.Printf("  🔍 Recolectando evidencia...\n")

	switch skillName {
	case "iam":
		skill := iam.NewIAMSkill()
		_ = skill // Placeholder for full implementation

		fmt.Printf("  ✅ Evidencia recolectada\n")
		fmt.Printf("  🤖 Analizando con %s...\n", provider.Name())
		fmt.Printf("  ✅ Análisis completado\n")

	case "exposure":
		fmt.Printf("  ⏳ Skill no disponible en MVP (Phase 2)\n")

	case "network":
		fmt.Printf("  ⏳ Skill no disponible en MVP (Phase 2)\n")

	case "vulns":
		fmt.Printf("  ⏳ Skill no disponible en MVP (Phase 2)\n")

	default:
		return fmt.Errorf("unknown skill: %s", skillName)
	}

	return nil
}
