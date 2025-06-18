package cmd

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/spf13/pflag"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"southwinds.dev/volta"
	"southwinds.dev/volta/audit"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile      string
	vaultPath    string
	passphrase   string
	tenantID     string
	vaultManager *volta.VaultManager
	vaultSvc     volta.VaultService
	auditLogger  audit.Logger
	cliContext   *CLIContext
)

type CLIContext struct {
	UserID    string
	SessionID string
	Source    string // hostname/IP
	StartTime time.Time
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vault",
	Short: "A secure embedded vault for managing secrets and encryption keys",
	Long: `A secure embedded vault that provides encryption key management and secret storage.
The vault uses AES-256-GCM encryption with automatic key rotation capabilities and 
secure memory protection for sensitive data.`,
	PersistentPreRunE: initializeVault,
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		if vaultSvc != nil {
			return vaultSvc.Close()
		}
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.vault.yaml)")
	rootCmd.PersistentFlags().StringVarP(&vaultPath, "vault-path", "p", ".vault", "path to vault storage")
	rootCmd.PersistentFlags().StringVar(&passphrase, "passphrase", "", "vault passphrase (or use VAULT_PASSPHRASE env var)")
	rootCmd.PersistentFlags().StringVarP(&tenantID, "tenant", "t", "default", "tenant identifier")

	// Bind flags to viper
	if err := viper.BindPFlag("vault.path", rootCmd.PersistentFlags().Lookup("vault-path")); err != nil {
		panic(fmt.Sprintf("failed to bind vault-path flag: %v", err))
	}
	if err := viper.BindPFlag("vault.passphrase", rootCmd.PersistentFlags().Lookup("passphrase")); err != nil {
		panic(fmt.Sprintf("failed to bind passphrase flag: %v", err))
	}
	if err := viper.BindPFlag("vault.tenant", rootCmd.PersistentFlags().Lookup("tenant")); err != nil {
		panic(fmt.Sprintf("failed to bind tenant flag: %v", err))
	}
	// Audit flags
	rootCmd.PersistentFlags().Bool("audit", false, "enable audit logging")
	rootCmd.PersistentFlags().String("audit-type", "file", "audit logger type (file, syslog)")
	rootCmd.PersistentFlags().String("audit-file", "", "audit log file path")
	rootCmd.PersistentFlags().Bool("audit-verbose", false, "enable verbose audit logging")

	// Bind audit flags
	if err := viper.BindPFlag("audit.enabled", rootCmd.PersistentFlags().Lookup("audit")); err != nil {
		panic(fmt.Sprintf("failed to bind audit enabled flag: %v", err))
	}
	if err := viper.BindPFlag("audit.type", rootCmd.PersistentFlags().Lookup("audit-type")); err != nil {
		panic(fmt.Sprintf("failed to bind audit type flag: %v", err))
	}
	if err := viper.BindPFlag("audit.options.file_path", rootCmd.PersistentFlags().Lookup("audit-file")); err != nil {
		panic(fmt.Sprintf("failed to bind audit options file_path flag: %v", err))
	}
	if err := viper.BindPFlag("audit.verbose", rootCmd.PersistentFlags().Lookup("audit-verbose")); err != nil {
		panic(fmt.Sprintf("failed to bind audit verbose file_path flag: %v", err))
	}
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".vault")
	}

	viper.SetEnvPrefix("VAULT")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
	}

	// Set audit defaults
	viper.SetDefault("audit.enabled", false)
	viper.SetDefault("audit.type", "file")
	viper.SetDefault("audit.options.file_path", filepath.Join(vaultPath, "audit.log"))
	viper.SetDefault("audit.options.max_size", 100)
	viper.SetDefault("audit.options.max_backups", 5)
	viper.SetDefault("audit.log_level", "info")
}

func initializeVault(cmd *cobra.Command, args []string) error {
	// Skip initialization for help and completion commands
	if cmd.Name() == "help" || cmd.Name() == "completion" || cmd.Name() == "__complete" {
		return nil
	}

	// Get configuration values
	vaultPath = viper.GetString("vault.path")
	if vaultPath == "" {
		vaultPath = ".volta"
	}

	tenantID = viper.GetString("vault.tenant")
	if tenantID == "" {
		tenantID = "default"
	}

	// Get passphrase from flag, config, or environment
	passphrase = viper.GetString("vault.passphrase")
	if passphrase == "" {
		passphrase = os.Getenv("VAULT_PASSPHRASE")
	}

	if passphrase == "" {
		return fmt.Errorf("vault passphrase is required. Use --passphrase flag or VAULT_PASSPHRASE environment variable")
	}

	// Create base vault directory if it doesn't exist
	if err := os.MkdirAll(vaultPath, 0700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	// Initialize vault manager with base options
	options := volta.Options{
		DerivationPassphrase: passphrase,
		EnvPassphraseVar:     "VAULT_PASSPHRASE",
	}

	// Initialize CLI context
	cliContext = &CLIContext{
		UserID:    getCurrentUser(),
		SessionID: generateSessionID(),
		Source:    getHostname(),
		StartTime: time.Now(),
	}

	auditLogger, _ = createAuditLogger()

	// Create vault manager with file store factory
	vaultManager = volta.NewVaultManagerFileStore(options, vaultPath, auditLogger)

	// Get vault for the specified tenant
	vs, err := vaultManager.GetVault(tenantID)
	if err != nil {
		return fmt.Errorf("failed to initialize vault for tenant %s: %w", tenantID, err)
	}
	vaultSvc = vs

	return nil
}

func createAuditLogger() (audit.Logger, error) {
	return audit.NewLogger(&audit.Config{
		Enabled:  true,
		TenantID: tenantID,
		Type:     audit.FileAuditType,
		Options: map[string]interface{}{
			"file_path": ".audit",
		},
		LogLevel: "",
	})
}

func auditCmdComplete(cmd *cobra.Command, err error, startedTime time.Time) error {
	// Log command completion
	if auditLogger != nil {
		auditLogger.Log("command_complete", err == nil, map[string]interface{}{
			"command":     cmd.CommandPath(),
			"duration_ms": time.Since(startedTime).Milliseconds(),
			"success":     err == nil,
			"error":       formatError(err),
			"user_id":     cliContext.UserID,
			"session_id":  cliContext.SessionID,
		})
	}
	return err
}

func auditCmdStart(cmd *cobra.Command, args []string) time.Time {
	now := time.Now()
	err := auditLogger.Log("command_start", true, map[string]interface{}{
		"command":    cmd.CommandPath(),
		"args":       sanitizeArgs(args),
		"flags":      sanitizeFlags(cmd),
		"user_id":    cliContext.UserID,
		"session_id": cliContext.SessionID,
		"source":     cliContext.Source,
	})
	if err != nil {
		log.Printf("ERROR: %v\n", err)
	}
	return now
}

func formatError(err error) string {
	if err == nil {
		return ""
	}

	var messages []string

	// Unwrap the error chain and collect all messages
	for err != nil {
		messages = append(messages, err.Error())
		err = errors.Unwrap(err)
	}

	// If we have multiple errors in the chain, show the hierarchy
	if len(messages) > 1 {
		// Remove duplicates that might occur from unwrapping
		uniqueMessages := make([]string, 0, len(messages))
		seen := make(map[string]bool)

		for _, msg := range messages {
			if !seen[msg] {
				uniqueMessages = append(uniqueMessages, msg)
				seen[msg] = true
			}
		}

		if len(uniqueMessages) > 1 {
			return fmt.Sprintf("Error: %s (caused by: %s)",
				uniqueMessages[0],
				strings.Join(uniqueMessages[1:], " -> "))
		}
	}

	// Single error or all messages were the same
	message := messages[0]

	// Basic formatting
	if len(message) > 0 {
		first := string(message[0])
		if first != strings.ToUpper(first) {
			message = strings.ToUpper(first) + message[1:]
		}
	}

	return fmt.Sprintf("Error: %s", message)
}

func sanitizeArgs(args []string) []string {
	// Remove or mask sensitive arguments
	sanitized := make([]string, len(args))
	for i, arg := range args {
		if containsSensitiveData(arg) {
			sanitized[i] = "[REDACTED]"
		} else {
			sanitized[i] = arg
		}
	}
	return sanitized
}

func containsSensitiveData(arg string) bool {
	// TODO: revise and implement
	return false
}

func sanitizeFlags(cmd *cobra.Command) map[string]interface{} {
	flags := make(map[string]interface{})
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Changed {
			if isSensitiveFlag(flag.Name) {
				flags[flag.Name] = "[REDACTED]"
			} else {
				flags[flag.Name] = flag.Value.String()
			}
		}
	})
	return flags
}

func isSensitiveFlag(name string) bool {
	sensitive := []string{"passphrase", "password", "secret", "key", "token"}
	lower := strings.ToLower(name)
	for _, s := range sensitive {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// getCurrentUser retrieves the username of the currently logged-in user.
// It returns "unknown_user" if the user cannot be determined.
func getCurrentUser() string {
	currentUser, err := user.Current()
	if err != nil {
		log.Printf("Warning: could not get current user: %v. Falling back to 'unknown_user'.", err)
		// This can happen in restricted environments or certain OSes (e.g., scratch Docker images without /etc/passwd)
		// You might also try OS-specific environment variables like USER or LOGNAME as a fallback.
		// For simplicity, we'll just return a default.
		envUser := os.Getenv("USER")
		if envUser != "" {
			return envUser
		}
		return "unknown_user"
	}
	return currentUser.Username
}

// generateSessionID creates a new unique session identifier.
// Uses UUID v4.
func generateSessionID() string {
	id := uuid.New()
	return id.String()
}

// getHostname retrieves the hostname of the machine.
// It returns "unknown_host" if the hostname cannot be determined.
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("Warning: could not get hostname: %v. Falling back to 'unknown_host'.", err)
		return "unknown_host"
	}
	return hostname
}
