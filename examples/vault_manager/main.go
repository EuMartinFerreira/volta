package main

import (
	"fmt"
	"log"
	"os"
	"southwinds.dev/volta"
	"southwinds.dev/volta/audit"
	"strings"
)

func main() {
	fmt.Println("### Example: Managing Multiple Tenant Vaults with FileStore ###")

	// 1. Define VaultManager Options
	// CRITICAL: DerivationSalt should be a unique, cryptographically random byte slice (e.g., 32 bytes),
	// kept secret and consistent for your application. Generate ONCE and store securely.
	// CRITICAL: DerivationPassphrase is a master passphrase for key derivation.
	// Store these securely (e.g., environment variables, hardware security module, dedicated secret manager).
	// DO NOT hardcode them in production code like this example.
	options := volta.Options{
		DerivationPassphrase: "Z5vmvP3^6UE*YwvjPZ5qZRJ7FoArSN57MRCQ@9fV2V7y&X3efYXht*LV#vX8", // Example: Load from secure env var or secret store
		// EnvPassphraseVar: "VOLTA_MASTER_PASSPHRASE", // Alternatively, set this env var and leave DerivationPassphrase empty
		EnableMemoryLock: true,  // Recommended: Attempts to lock sensitive memory pages in RAM.
		Debug:            false, // Set to true for more verbose internal logging from Volta library.
	}

	// 2. Setup Audit Logger
	// This logger will receive events for actions performed by the VaultManager and Vaults.
	auditLogger, err := createAuditLogger()
	if err != nil {
		log.Fatalf("Failed to create audit logger: %v", err)
	}
	fmt.Println("Audit logger initialized.")

	// 3. Define Base Path for Vault Storage
	// This is the root directory where encrypted vault files for each tenant will be stored.
	// Ensure this path is secure and has appropriate permissions in production.
	basePath, err := os.MkdirTemp("", "volta_filestore_example_")
	if err != nil {
		log.Fatalf("Failed to create temporary directory for basePath: %v", err)
	}
	// Defer cleanup of the temporary directory for this example.
	// In production, this directory must persist and be secured.
	defer func() {
		fmt.Printf("Cleaning up temporary vault storage path: %s\n", basePath)
		os.RemoveAll(basePath)
	}()
	fmt.Printf("Using temporary vault storage path: %s (in production, use a persistent, secure path)\n", basePath)

	// 4. Create the VaultManager instance using NewVaultManagerFileStore
	// This vaultManager will manage multiple tenant vaults, each stored as an encrypted file
	// within the basePath directory.
	vaultManager := volta.NewVaultManagerFileStore(options, basePath, auditLogger)

	fmt.Println("VaultManager initialized successfully!")
	fmt.Println("Ready to manage vaults for different tenants.")

	// --- Operations for Tenant 001 ---
	fmt.Println("\n--- Tenant 001 Operations ---")
	tenant001Id := "tenant-001-alpha"
	tenant001SecretID := "my-super-secret-t1"
	tenant001SecretValue := "QWERTYUIOPasdfghjkl123"

	// Get the vault for tenant 001
	vault001, err := vaultManager.GetVault(tenant001Id)
	if err != nil {
		// This error might indicate the vault doesn't exist if GetVault doesn't create.
		// Or it could be a decryption error if it exists but manager config is wrong.
		log.Fatalf("Failed to get vault for tenant %s: %v", tenant001Id, err)
	}
	fmt.Printf("Successfully obtained vault for tenant: %s. Ready for secret operations.\n", tenant001Id)

	// Store a secret for tenant 001
	_, err = vault001.StoreSecret(tenant001SecretID, []byte(tenant001SecretValue), []string{"test", "example1", "owner:team-a"}, volta.ContentTypeText)
	if err != nil {
		log.Fatalf("Failed to store secret '%s' for tenant %s: %v", tenant001SecretID, tenant001Id, err)
	}
	fmt.Printf("Stored secret '%s' for tenant %s.\n", tenant001SecretID, tenant001Id)

	// Use the secret for tenant 001
	err = vault001.UseSecret(tenant001SecretID, func(retrievedData []byte) error {
		fmt.Printf("Tenant %s, Secret '%s': Callback invoked. Received %d bytes.\n", tenant001Id, tenant001SecretID, len(retrievedData))
		// Example of using and verifying the secret within the callback
		if !strings.EqualFold(string(retrievedData), tenant001SecretValue) {
			// The secret content does not match what was expected.
			return fmt.Errorf("retrieved secret value ('%s') does not match expected value ('%s')", string(retrievedData), tenant001SecretValue)
		}
		fmt.Printf("Tenant %s, Secret '%s': Content verified successfully. (Simulating use...)\n", tenant001Id, tenant001SecretID)
		// Simulate doing something with the secret here, e.g., configuring a client, making an API call.
		return nil // Indicate successful processing of the secret within the callback
	})
	if err != nil {
		log.Fatalf("Failed to use secret '%s' for tenant %s: %v", tenant001SecretID, tenant001Id, err)
	}
	fmt.Printf("Successfully used secret '%s' for tenant %s.\n", tenant001SecretID, tenant001Id)

	// Close the vault for tenant 001 (if required by your library to release resources or flush data)
	if err = vault001.Close(); err != nil {
		// Non-fatal, as other operations might continue or cleanup might handle it.
		// But good to log.
		fmt.Printf("Warning: error closing vault for tenant %s: %v\n", tenant001Id, err)
	} else {
		fmt.Printf("Vault for tenant %s closed.\n", tenant001Id)
	}

	// --- Operations for Tenant 002 ---
	fmt.Println("\n--- Tenant 002 Operations ---")
	tenant002Id := "tenant-002-beta"
	tenant002SecretID := "another-db-credential-t2"
	tenant002SecretValue := "dslknvceonertv0_XYZ987"

	vault002, err := vaultManager.GetVault(tenant002Id)
	if err != nil {
		log.Fatalf("Failed to get vault for tenant %s: %v", tenant002Id, err)
	}
	fmt.Printf("Successfully obtained vault for tenant: %s. Ready for secret operations.\n", tenant002Id)

	// Store a secret for tenant 002
	_, err = vault002.StoreSecret(tenant002SecretID, []byte(tenant002SecretValue), []string{"database", "credentials", "environment:staging"}, volta.ContentTypeBinary) // Example with Binary
	if err != nil {
		log.Fatalf("Failed to store secret '%s' for tenant %s: %v", tenant002SecretID, tenant002Id, err)
	}
	fmt.Printf("Stored secret '%s' for tenant %s.\n", tenant002SecretID, tenant002Id)

	// Use the secret for tenant 002
	err = vault002.UseSecret(tenant002SecretID, func(retrievedData []byte) error {
		fmt.Printf("Tenant %s, Secret '%s': Callback invoked. Received %d bytes.\n", tenant002Id, tenant002SecretID, len(retrievedData))
		if !strings.EqualFold(string(retrievedData), tenant002SecretValue) {
			return fmt.Errorf("retrieved secret value ('%s') does not match expected value ('%s')", string(retrievedData), tenant002SecretValue)
		}
		fmt.Printf("Tenant %s, Secret '%s': Content verified successfully. (Simulating use...)\n", tenant002Id, tenant002SecretID)
		return nil
	})
	if err != nil {
		log.Fatalf("Failed to use secret '%s' for tenant %s: %v", tenant002SecretID, tenant002Id, err)
	}
	fmt.Printf("Successfully used secret '%s' for tenant %s.\n", tenant002SecretID, tenant002Id)

	// Close the vault for tenant 002
	if err = vault002.Close(); err != nil {
		fmt.Printf("Warning: error closing vault for tenant %s: %v\n", tenant002Id, err)
	} else {
		fmt.Printf("Vault for tenant %s closed.\n", tenant002Id)
	}

	fmt.Println("\n### Example Completed ###")
}

// createAuditLogger initializes an audit logger based on the volta audit package.
func createAuditLogger() (audit.Logger, error) {
	auditFilePath := ".volta_audit.log"
	fmt.Printf("Initializing file-based audit logger at: %s\n", auditFilePath)

	return audit.NewLogger(&audit.Config{
		Enabled: true,
		Type:    audit.FileAuditType, // Assuming FileAuditType is a defined constant (e.g., "file")
		Options: map[string]interface{}{
			"file_path": auditFilePath, // e.g., "/var/log/volta_audit.jsonl" in production
			// Other options might include "max_size_mb", "max_backups", "compress", etc.
		},
	})
}
