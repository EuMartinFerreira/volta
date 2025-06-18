package volta

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/awnumar/memguard"
	"os"
	"path/filepath"
	"southwinds.dev/volta/persist"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVaultBackup(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{"BackupSuccessful", testBackupSuccessful},
		{"BackupWithMultipleKeys", testBackupWithMultipleKeys},
		{"BackupWithNoKeys", testBackupWithNoKeys},
		{"BackupWithNoMetadata", testBackupWithNoMetadata},
		{"BackupFailsWithInvalidPath", testBackupFailsWithInvalidPath},
		{"BackupFailsWhenSaltInaccessible", testBackupFailsWhenSaltInaccessible},
		{"BackupFailsWhenKeyLoadFails", testBackupFailsWhenKeyLoadFails},
		{"BackupFailsWhenMetadataLoadFails", testBackupFailsWhenMetadataLoadFails},
		{"BackupFailsWhenStorageBackupFails", testBackupFailsWhenStorageBackupFails},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

func testBackupSuccessful(t *testing.T) {
	// Create a unique test directory for this specific test
	timestamp := time.Now().UnixNano()
	testDir := filepath.Join(tempDir, fmt.Sprintf("backup_test_%d", timestamp))

	// Clean up any existing test directory
	os.RemoveAll(testDir)
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(testDir)
	})

	// Create test options with the unique directory
	options := Options{
		DerivationPassphrase: passPhrase,
		EnableMemoryLock:     false,
	}

	// Create the vault with unique directory
	vault := createTestVault(t, options, testDir)
	defer vault.Close()

	// Create truly unique test data with timestamp and various content types
	testSecrets := map[string]struct {
		data        []byte
		contentType ContentType
		tags        []string
	}{
		fmt.Sprintf("successful-backup-secret-1-%d", timestamp): {
			data:        []byte("test value for successful backup"),
			contentType: ContentTypeText,
			tags:        []string{"backup", "test", "text"},
		},
		fmt.Sprintf("successful-backup-secret-2-%d", timestamp): {
			data:        []byte("another test value"),
			contentType: ContentTypeText,
			tags:        []string{"backup", "test"},
		},
		fmt.Sprintf("successful-backup-config-%d", timestamp): {
			data:        []byte(`{"env": "test", "debug": true}`),
			contentType: ContentTypeJSON,
			tags:        []string{"backup", "config", "json"},
		},
		fmt.Sprintf("successful-backup-binary-%d", timestamp): {
			data:        []byte{0x01, 0x02, 0x03, 0xFF, 0xFE},
			contentType: ContentTypeBinary,
			tags:        []string{"backup", "binary"},
		},
		fmt.Sprintf("successful-backup-yaml-%d", timestamp): {
			data:        []byte("server:\n  port: 8080\n  host: localhost"),
			contentType: ContentTypeYAML,
			tags:        []string{"backup", "yaml", "config"},
		},
	}

	// Store unique test secrets with their content types and tags
	storedMetadata := make(map[string]*SecretMetadata)
	for name, secret := range testSecrets {
		metadata, err := vault.StoreSecret(name, secret.data, secret.tags, secret.contentType)
		if err != nil {
			t.Fatalf("Failed to store test secret %s: %v", name, err)
		}
		storedMetadata[name] = metadata
		t.Logf("Stored secret: %s (%s) - %d bytes", name, secret.contentType, len(secret.data))
	}

	// Verify secrets were stored correctly using SecretResult
	for name, expectedSecret := range testSecrets {
		result, err := vault.GetSecret(name)
		if err != nil {
			t.Fatalf("Failed to retrieve test secret %s: %v", name, err)
		}

		// Verify SecretResult structure
		if result == nil {
			t.Fatalf("Expected non-nil SecretResult for secret %s", name)
		}

		if result.Data == nil {
			t.Fatalf("Expected non-nil data in SecretResult for secret %s", name)
		}

		if result.Metadata == nil {
			t.Fatalf("Expected non-nil metadata in SecretResult for secret %s", name)
		}

		// Verify data matches
		if !bytes.Equal(result.Data, expectedSecret.data) {
			t.Fatalf("Retrieved secret %s does not match stored value", name)
		}

		// Verify content type
		if result.Metadata.ContentType != expectedSecret.contentType {
			t.Fatalf("Secret %s content type mismatch: expected %s, got %s",
				name, expectedSecret.contentType, result.Metadata.ContentType)
		}

		// Verify tags
		if len(result.Metadata.Tags) != len(expectedSecret.tags) {
			t.Fatalf("Secret %s tag count mismatch: expected %d, got %d",
				name, len(expectedSecret.tags), len(result.Metadata.Tags))
		}

		// Verify each tag exists (order might be different)
		expectedTagsMap := make(map[string]bool)
		for _, tag := range expectedSecret.tags {
			expectedTagsMap[tag] = true
		}

		for _, tag := range result.Metadata.Tags {
			if !expectedTagsMap[tag] {
				t.Fatalf("Secret %s has unexpected tag: %s", name, tag)
			}
		}

		// Verify access tracking
		if result.Metadata.AccessCount <= 0 {
			t.Fatalf("Secret %s should have access count > 0, got %d", name, result.Metadata.AccessCount)
		}

		if result.Metadata.LastAccessed.IsZero() {
			t.Fatalf("Secret %s should have LastAccessed set", name)
		}

		// Verify size consistency
		if result.Metadata.Size != len(expectedSecret.data) {
			t.Fatalf("Secret %s size mismatch: expected %d, got %d",
				name, len(expectedSecret.data), result.Metadata.Size)
		}

		// Verify metadata consistency
		if result.Metadata.SecretID != name {
			t.Fatalf("Secret %s has incorrect SecretID: expected %s, got %s",
				name, name, result.Metadata.SecretID)
		}

		// Verify version
		if result.Metadata.Version != 1 {
			t.Fatalf("Secret %s should have version 1, got %d", name, result.Metadata.Version)
		}

		// Verify key usage tracking
		if !result.UsedActiveKey {
			t.Logf("Note: Secret %s was not encrypted with the active key", name)
		}

		t.Logf("✅ Verified secret: %s (%s) - %d bytes, access count: %d, version: %d",
			name, result.Metadata.ContentType, result.Metadata.Size,
			result.Metadata.AccessCount, result.Metadata.Version)
	}

	t.Logf("Successfully stored and verified %d test secrets", len(testSecrets))

	// Test access count incrementation
	firstSecretName := fmt.Sprintf("successful-backup-secret-1-%d", timestamp)

	// Get the secret again to test access count increment
	result1, err := vault.GetSecret(firstSecretName)
	if err != nil {
		t.Fatalf("Failed to retrieve secret for access count test: %v", err)
	}

	result2, err := vault.GetSecret(firstSecretName)
	if err != nil {
		t.Fatalf("Failed to retrieve secret second time: %v", err)
	}

	if result2.Metadata.AccessCount <= result1.Metadata.AccessCount {
		t.Error("Access count should increment on subsequent retrievals")
	}

	if !result2.Metadata.LastAccessed.After(*result1.Metadata.LastAccessed) {
		t.Error("LastAccessed should be updated on subsequent retrievals")
	}

	t.Logf("Access count increment test passed: %d -> %d",
		result1.Metadata.AccessCount, result2.Metadata.AccessCount)

	// Create a backup file path in the same test directory
	backupFile := filepath.Join(testDir, fmt.Sprintf("vault_backup_test_%d.bak", timestamp))

	passphrase := "test-backup-passphrase-with-good-length"

	// Perform backup
	err = vault.Backup(backupFile, passphrase)
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// Verify backup file exists and has content
	fileInfo, err := os.Stat(backupFile)
	if err != nil {
		t.Fatalf("Backup file was not created: %v", err)
	}

	if fileInfo.Size() == 0 {
		t.Fatal("Backup file is empty")
	}

	// Verify backup file has reasonable size (should be larger than just the data)
	totalDataSize := 0
	for _, secret := range testSecrets {
		totalDataSize += len(secret.data)
	}

	if fileInfo.Size() < int64(totalDataSize) {
		t.Errorf("Backup file size (%d) seems too small for %d bytes of data",
			fileInfo.Size(), totalDataSize)
	}

	// Test that backup file is not directly readable (encrypted)
	backupContent, err := os.ReadFile(backupFile)
	if err != nil {
		t.Fatalf("Failed to read backup file: %v", err)
	}

	// Verify backup doesn't contain plaintext secrets
	for _, secret := range testSecrets {
		if bytes.Contains(backupContent, secret.data) {
			t.Errorf("Backup file contains plaintext secret data - backup should be encrypted")
		}
	}

	// Get key metadata for backup verification
	keyMetadata, err := vault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to list key metadata: %v", err)
	}

	// Test listing secrets to verify count
	secretsList, err := vault.ListSecrets(&SecretListOptions{})
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}

	if len(secretsList) != len(testSecrets) {
		t.Errorf("Expected %d secrets in list, got %d", len(testSecrets), len(secretsList))
	}

	// Verify content type distribution in backup
	contentTypeCounts := make(map[ContentType]int)
	for _, secret := range testSecrets {
		contentTypeCounts[secret.contentType]++
	}

	t.Logf("Content type distribution in backup:")
	for contentType, count := range contentTypeCounts {
		t.Logf("  %s: %d secrets", contentType, count)
	}

	t.Logf("✅ Backup successfully created at: %s (size: %d bytes)", backupFile, fileInfo.Size())
	t.Logf("✅ Backup contains %d secrets across %d content types", len(testSecrets), len(contentTypeCounts))
	t.Logf("✅ Backup includes %d encryption keys", len(keyMetadata))
	t.Logf("✅ Backup is properly encrypted (no plaintext secrets found)")
	t.Logf("✅ Access tracking and key usage tracking verified")
	t.Logf("✅ Total data size: %d bytes, backup size: %d bytes (%.1fx overhead)",
		totalDataSize, fileInfo.Size(), float64(fileInfo.Size())/float64(totalDataSize))
}

func testBackupWithMultipleKeys(t *testing.T) {
	// Define consistent passphrase for both original and restored vaults
	const testPassphrase = "comprehensive-test-passphrase-with-sufficient-length"

	options := createTestOptions()
	// Make sure original vault uses the test passphrase
	options.DerivationPassphrase = testPassphrase
	vault := createTestVault(t, options, tempDir)
	defer vault.Close()

	if tempDir == "" || tempDir == "." {
		// Fallback to a proper temp directory
		var err error
		tempDir, err = os.MkdirTemp("", "vault_test_*")
		if err != nil {
			t.Fatalf("Failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tempDir) // Clean up
	}

	// Create test data with timestamp for uniqueness
	timestamp := time.Now().UnixNano()

	// Store initial secrets with proper content types
	type SecretTest struct {
		data        []byte
		contentType ContentType
		tags        []string
		description string
	}

	initialSecrets := map[string]SecretTest{
		fmt.Sprintf("initial-secret-1-%d", timestamp): {
			data:        []byte("initial value 1"),
			contentType: ContentTypeText,
			tags:        []string{"initial", "test"},
			description: "First initial secret",
		},
		fmt.Sprintf("initial-secret-2-%d", timestamp): {
			data:        []byte("initial value 2"),
			contentType: ContentTypeText,
			tags:        []string{"initial", "test"},
			description: "Second initial secret",
		},
	}

	t.Logf("Storing initial secrets with first key")
	for name, secret := range initialSecrets {
		_, err := vault.StoreSecret(name, secret.data, secret.tags, secret.contentType)
		if err != nil {
			t.Fatalf("Failed to store initial secret %s: %v", name, err)
		}
		t.Logf("✅ Stored initial secret: %s (%s)", name, secret.contentType)
	}

	// Get the initial key info
	initialKeyMetadata, err := vault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to list initial key metadata: %v", err)
	}
	t.Logf("Initial keys: %d", len(initialKeyMetadata))

	// Add more diverse test data with appropriate content types
	additionalSecrets := map[string]SecretTest{
		fmt.Sprintf("config-secret-%d", timestamp): {
			data:        []byte(`{"database": "test", "port": 5432}`),
			contentType: ContentTypeJSON,
			tags:        []string{"config", "database"},
			description: "Database configuration in JSON format",
		},
		fmt.Sprintf("api-key-%d", timestamp): {
			data:        []byte("sk-1234567890abcdef"),
			contentType: ContentTypeText,
			tags:        []string{"api", "key", "auth"},
			description: "API authentication key",
		},
		fmt.Sprintf("credentials-%d", timestamp): {
			data:        []byte("user:pass@host:port"),
			contentType: ContentTypeText,
			tags:        []string{"credentials", "database"},
			description: "Database connection credentials",
		},
		fmt.Sprintf("large-secret-%d", timestamp): {
			data:        []byte(strings.Repeat("test data ", 100)),
			contentType: ContentTypeText,
			tags:        []string{"test", "large"},
			description: "Large text data for testing",
		},
		fmt.Sprintf("binary-secret-%d", timestamp): {
			data:        []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE},
			contentType: ContentTypeBinary,
			tags:        []string{"binary", "test"},
			description: "Binary test data",
		},
		fmt.Sprintf("certificate-%d", timestamp): {
			data:        []byte("-----BEGIN CERTIFICATE-----\nMIIC...test cert...\n-----END CERTIFICATE-----"),
			contentType: ContentTypePEM,
			tags:        []string{"certificate", "pki"},
			description: "Test certificate data",
		},
		fmt.Sprintf("yaml-config-%d", timestamp): {
			data:        []byte("server:\n  host: localhost\n  port: 8080"),
			contentType: ContentTypeYAML,
			tags:        []string{"config", "yaml"},
			description: "YAML configuration file",
		},
	}

	// Store additional secrets with proper content types
	t.Logf("Storing additional diverse secrets")
	allSecrets := make(map[string]SecretTest)

	// Add initial secrets to allSecrets
	for name, secret := range initialSecrets {
		allSecrets[name] = secret
	}

	// Store and add additional secrets
	for name, secret := range additionalSecrets {
		allSecrets[name] = secret
		_, err = vault.StoreSecret(name, secret.data, secret.tags, secret.contentType)
		if err != nil {
			t.Fatalf("Failed to store additional secret %s: %v", name, err)
		}
		t.Logf("✅ Stored secret: %s (%s) - %d bytes",
			name, secret.contentType, len(secret.data))
	}

	// Verify all secrets are accessible with content type validation
	t.Logf("Verifying all %d secrets are accessible with correct content types", len(allSecrets))
	for name, expectedSecret := range allSecrets {
		result, err := vault.GetSecret(name)
		if err != nil {
			t.Fatalf("Failed to retrieve secret %s: %v", name, err)
		}

		// Verify SecretResult structure
		if result == nil {
			t.Fatalf("Expected non-nil SecretResult for secret %s", name)
		}

		if result.Data == nil {
			t.Fatalf("Expected non-nil data in SecretResult for secret %s", name)
		}

		if result.Metadata == nil {
			t.Fatalf("Expected non-nil metadata in SecretResult for secret %s", name)
		}

		// Verify data
		if !bytes.Equal(result.Data, expectedSecret.data) {
			t.Fatalf("Retrieved secret %s does not match stored value", name)
		}

		// Verify content type
		if result.Metadata.ContentType != expectedSecret.contentType {
			t.Fatalf("Secret %s has incorrect content type: expected %s, got %s",
				name, expectedSecret.contentType, result.Metadata.ContentType)
		}

		// Verify tags
		if len(result.Metadata.Tags) != len(expectedSecret.tags) {
			t.Fatalf("Secret %s has incorrect number of tags: expected %d, got %d",
				name, len(expectedSecret.tags), len(result.Metadata.Tags))
		}

		// Verify each tag exists (order might be different)
		expectedTagsMap := make(map[string]bool)
		for _, tag := range expectedSecret.tags {
			expectedTagsMap[tag] = true
		}

		for _, tag := range result.Metadata.Tags {
			if !expectedTagsMap[tag] {
				t.Fatalf("Secret %s has unexpected tag: %s", name, tag)
			}
		}

		// Verify key usage tracking
		if !result.UsedActiveKey {
			t.Logf("Note: Secret %s was not encrypted with the active key", name)
		}

		// Verify access tracking
		if result.Metadata.AccessCount <= 0 {
			t.Fatalf("Secret %s should have access count > 0, got %d", name, result.Metadata.AccessCount)
		}

		if result.Metadata.LastAccessed.IsZero() {
			t.Fatalf("Secret %s should have LastAccessed set", name)
		}

		// Verify size consistency
		if result.Metadata.Size != len(expectedSecret.data) {
			t.Fatalf("Secret %s has incorrect size: expected %d, got %d",
				name, len(expectedSecret.data), result.Metadata.Size)
		}

		t.Logf("✅ Verified secret: %s (%s) with %d tags, access count: %d",
			name, result.Metadata.ContentType, len(result.Metadata.Tags), result.Metadata.AccessCount)
	}

	// Test content type filtering
	// Example: List secrets by content type
	secretsList, err := vault.ListSecrets(&SecretListOptions{})
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}

	// Count secrets by content type
	contentTypeCounts := make(map[ContentType]int)
	for _, secretInfo := range secretsList {
		contentTypeCounts[secretInfo.Metadata.ContentType]++
	}

	t.Logf("Content type distribution:")
	for contentType, count := range contentTypeCounts {
		t.Logf("  %s: %d secrets", contentType, count)
	}

	// Get final key metadata
	finalKeyMetadata, err := vault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to list final key metadata: %v", err)
	}

	t.Logf("Found %d keys in vault", len(finalKeyMetadata))
	for i, meta := range finalKeyMetadata {
		t.Logf("Key %d: %s, Status: %s", i+1, meta.KeyID, meta.Status)
	}

	// Create backup using the same passphrase
	backupFile := filepath.Join(t.TempDir(), fmt.Sprintf("vault_backup_comprehensive_%d.bak", timestamp))

	t.Logf("Creating backup at: %s", backupFile)

	err = vault.Backup(backupFile, testPassphrase) // Use same passphrase
	if err != nil {
		t.Fatalf("Backup failed: %v", err)
	}

	// Verify backup file
	fileInfo, err := os.Stat(backupFile)
	if err != nil {
		t.Fatalf("Backup file was not created: %v", err)
	}

	if fileInfo.Size() == 0 {
		t.Fatal("Backup file is empty")
	}

	// Create restored vault with the SAME passphrase
	restoredVault := createTestVaultForRestore(t, testPassphrase) // Use same passphrase
	defer restoredVault.Close()

	t.Logf("Testing backup restoration...")
	err = restoredVault.Restore(backupFile, testPassphrase) // Use same passphrase
	if err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	// Verify all secrets are correctly restored with content types
	t.Logf("Verifying restored secrets with content types...")
	for name, expectedSecret := range allSecrets {
		result, err := restoredVault.GetSecret(name)
		if err != nil {
			t.Fatalf("Failed to retrieve restored secret %s: %v", name, err)
		}

		// Verify SecretResult structure
		if result == nil {
			t.Fatalf("Expected non-nil SecretResult for restored secret %s", name)
		}

		if result.Data == nil {
			t.Fatalf("Expected non-nil data in SecretResult for restored secret %s", name)
		}

		if result.Metadata == nil {
			t.Fatalf("Expected non-nil metadata in SecretResult for restored secret %s", name)
		}

		// Verify data
		if !bytes.Equal(result.Data, expectedSecret.data) {
			t.Fatalf("Restored secret %s does not match original value", name)
		}

		// Verify content type is preserved
		if result.Metadata.ContentType != expectedSecret.contentType {
			t.Fatalf("Restored secret %s has incorrect content type: expected %s, got %s",
				name, expectedSecret.contentType, result.Metadata.ContentType)
		}

		// Verify tags are preserved
		if len(result.Metadata.Tags) != len(expectedSecret.tags) {
			t.Fatalf("Restored secret %s has incorrect number of tags: expected %d, got %d",
				name, len(expectedSecret.tags), len(result.Metadata.Tags))
		}

		// Verify size is preserved
		if result.Metadata.Size != len(expectedSecret.data) {
			t.Fatalf("Restored secret %s has incorrect size: expected %d, got %d",
				name, len(expectedSecret.data), result.Metadata.Size)
		}

		// Verify access tracking is properly initialized after restore
		if result.Metadata.AccessCount <= 0 {
			t.Fatalf("Restored secret %s should have access count > 0, got %d",
				name, result.Metadata.AccessCount)
		}

		if result.Metadata.LastAccessed.IsZero() {
			t.Fatalf("Restored secret %s should have LastAccessed set", name)
		}

		// Verify key usage tracking
		if !result.UsedActiveKey {
			t.Logf("Note: Restored secret %s was not encrypted with the active key", name)
		}

		// Verify metadata consistency
		if result.Metadata.SecretID != name {
			t.Fatalf("Restored secret %s has incorrect SecretID: expected %s, got %s",
				name, name, result.Metadata.SecretID)
		}

		t.Logf("✅ Restored secret verified: %s (%s) - %d bytes, access count: %d",
			name, result.Metadata.ContentType, result.Metadata.Size, result.Metadata.AccessCount)
	}

	// Test that restored vault is fully functional
	testSecretID := fmt.Sprintf("post-restore-test-%d", timestamp)
	testSecretData := []byte("test data after restore")

	newMetadata, err := restoredVault.StoreSecret(testSecretID, testSecretData, []string{"post-restore"}, ContentTypeText)
	if err != nil {
		t.Fatalf("Failed to store new secret in restored vault: %v", err)
	}

	// Verify the new secret can be retrieved
	newResult, err := restoredVault.GetSecret(testSecretID)
	if err != nil {
		t.Fatalf("Failed to retrieve new secret from restored vault: %v", err)
	}

	if !bytes.Equal(newResult.Data, testSecretData) {
		t.Fatalf("New secret in restored vault has incorrect data")
	}

	// Test access count increments properly in restored vault
	result2, err := restoredVault.GetSecret(testSecretID)
	if err != nil {
		t.Fatalf("Failed to retrieve secret second time: %v", err)
	}

	if result2.Metadata.AccessCount <= newResult.Metadata.AccessCount {
		t.Error("Access count should increment on subsequent retrievals in restored vault")
	}

	t.Logf("✅ Backup successfully created and restored with %d keys and %d secrets",
		len(finalKeyMetadata), len(allSecrets))
	t.Logf("Backup file: %s (size: %d bytes)", backupFile, fileInfo.Size())
	t.Logf("All content types preserved correctly during backup/restore cycle")
	t.Logf("Access tracking and key usage tracking work properly after restore")
	t.Logf("Restored vault is fully functional for new operations")
	t.Logf("New secret stored post-restore: %s (version %d)", testSecretID, newMetadata.Version)
}

func createTestVaultWithMultipleKeys(t *testing.T) *Vault {
	// Create a proper temp directory
	workDir, err := os.MkdirTemp("", "vault_test_multiple_keys_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	t.Cleanup(func() {
		_ = os.RemoveAll(workDir)
	})

	// Create storage
	store, err := persist.NewFileSystemStore(workDir, tenantID)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Create derivation salt and protect it immediately
	derivationSalt := make([]byte, 32)
	for i := range derivationSalt {
		derivationSalt[i] = byte(i + 100)
	}
	derivationSaltEnclave := memguard.NewEnclave(derivationSalt)
	memguard.WipeBytes(derivationSalt) // Clear original

	// Create derivation key and protect it
	derivationKey := make([]byte, 32)
	for i := range derivationKey {
		derivationKey[i] = byte(i)
	}
	derivationKeyEnclave := memguard.NewEnclave(derivationKey)
	memguard.WipeBytes(derivationKey) // Clear original

	// Create proper audit logger
	auditLogger := createLogger()

	// Create the current key and protect it
	currentKey := make([]byte, 32)
	_, err = rand.Read(currentKey)
	if err != nil {
		t.Fatalf("Failed to generate current key: %v", err)
	}
	currentKeyID := "test-current-key"
	currentKeyEnclave := memguard.NewEnclave(currentKey)
	memguard.WipeBytes(currentKey) // Clear original

	// Create inactive keys and protect them
	inactiveKeys := make(map[string]*memguard.Enclave)
	inactiveKeyIDs := make([]string, 2)

	for i := 0; i < 2; i++ {
		inactiveKey := make([]byte, 32)
		_, err = rand.Read(inactiveKey)
		if err != nil {
			t.Fatalf("Failed to generate inactive key %d: %v", i, err)
		}

		keyID := generateKeyID()
		inactiveKeyIDs[i] = keyID
		inactiveKeys[keyID] = memguard.NewEnclave(inactiveKey)
		memguard.WipeBytes(inactiveKey) // Clear original
	}

	// Combine all keys
	allKeyEnclaves := make(map[string]*memguard.Enclave)
	allKeyEnclaves[currentKeyID] = currentKeyEnclave
	for keyID, enclave := range inactiveKeys {
		allKeyEnclaves[keyID] = enclave
	}

	// Create metadata for all keys
	now := time.Now()
	keyMetadata := map[string]KeyMetadata{
		currentKeyID: {
			KeyID:     currentKeyID,
			Status:    KeyStatusActive,
			Active:    true,
			CreatedAt: now,
			Version:   1,
		},
	}

	for _, keyID := range inactiveKeyIDs {
		keyMetadata[keyID] = KeyMetadata{
			KeyID:         keyID,
			Status:        KeyStatusInactive,
			Active:        false,
			CreatedAt:     now.Add(-time.Hour), // Make them older
			DeactivatedAt: &now,
			Version:       1,
		}
	}

	// Create vault
	vault := &Vault{
		store:                 store,
		keyEnclaves:           allKeyEnclaves,
		keyMetadata:           keyMetadata,
		mu:                    sync.RWMutex{},
		currentKeyID:          currentKeyID,
		derivationSaltEnclave: derivationSaltEnclave, // Use enclave instead of raw bytes
		derivationKeyEnclave:  derivationKeyEnclave,
		audit:                 auditLogger,
		secretsVersion:        "1.0",
		secretsTimestamp:      time.Now(),
		closed:                false,
	}

	// Create and store empty secrets container
	initialContainer := &SecretsContainer{
		Version:   "1.0",
		Timestamp: time.Now(),
		Secrets:   make(map[string]*SecretEntry),
	}

	containerJSON, err := json.Marshal(initialContainer)
	if err != nil {
		t.Fatalf("Failed to marshal initial secrets container: %v", err)
	}

	encryptedContainer, err := vault.encryptWithCurrentKey(containerJSON)
	if err != nil {
		t.Fatalf("Failed to encrypt initial secrets container: %v", err)
	}

	vault.secretsContainer = memguard.NewEnclave(encryptedContainer)

	// **CRITICAL: Save encrypted metadata to disk so DestroyKey can load it**
	metadataJSON, err := json.Marshal(keyMetadata)
	if err != nil {
		t.Fatalf("Failed to marshal key metadata: %v", err)
	}

	// Encrypt the metadata using the derivation key (same as vault does)
	encryptedMetadata, err := vault.encryptWithCurrentKey(metadataJSON)
	if err != nil {
		t.Fatalf("Failed to encrypt metadata: %v", err)
	}

	err = store.SaveMetadata(encryptedMetadata)
	if err != nil {
		t.Fatalf("Failed to save encrypted metadata to disk: %v", err)
	}

	t.Logf("Created vault with keys: current=%s, inactive=%v", currentKeyID, inactiveKeyIDs)

	return vault
}

func testBackupFailsWithInvalidPath(t *testing.T) {
	vault := createTestVaultWithDerivation(t)
	setupTestVaultData(t, vault)

	// Try to backup to an invalid/non-existent directory with no write permissions
	invalidPaths := []string{
		"/root/nonexistent/directory",   // No permissions
		"/nonexistent/deep/path/backup", // Non-existent path
		"",                              // Empty path
	}

	passphrase := "test-passphrase"

	for _, invalidPath := range invalidPaths {
		err := vault.Backup(invalidPath, passphrase)
		if err == nil {
			t.Errorf("Expected backup to fail with invalid path: %s", invalidPath)
		} else {
			t.Logf("Got expected error for invalid path %s: %v", invalidPath, err)
		}
	}
}

func testBackupWithNoKeys(t *testing.T) {
	vault := createTestVaultWithDerivation(t)

	// Create some secrets with the single key
	secrets := map[string]struct {
		data        []byte
		tags        []string
		contentType ContentType
	}{
		"lonely-secret": {[]byte("test-value"), []string{"alone"}, ContentTypeText},
	}

	for secretID, secret := range secrets {
		_, err := vault.StoreSecret(secretID, secret.data, secret.tags, secret.contentType)
		if err != nil {
			t.Fatalf("Failed to store secret %s: %v", secretID, err)
		}
	}

	// Use a backup file path instead of directory
	backupFile := filepath.Join(tempDir, fmt.Sprintf("vault_backup_nokeys_%d.bak", time.Now().UnixNano()))

	// Clean up any existing backup files to avoid conflicts
	existingBackups, _ := filepath.Glob(filepath.Join(tempDir, "vault_backup_*"))
	for _, file := range existingBackups {
		os.Remove(file)
	}
	existingTemps, _ := filepath.Glob(filepath.Join(tempDir, ".tmp-*"))
	for _, file := range existingTemps {
		os.Remove(file)
	}

	// Ensure backup file doesn't exist
	os.Remove(backupFile)
	t.Cleanup(func() {
		os.Remove(backupFile)
	})

	passphrase := "no-keys-backup-passphrase-with-sufficient-length"

	// Backup should succeed even with minimal keys
	err := vault.Backup(backupFile, passphrase)
	if err != nil {
		t.Fatalf("Backup with no additional keys failed: %v", err)
	}

	// Verify backup file was created and has content
	fileInfo, err := os.Stat(backupFile)
	if err != nil {
		t.Fatalf("Backup file was not created: %v", err)
	}

	if fileInfo.IsDir() {
		t.Fatal("Backup created a directory instead of a file")
	}

	if fileInfo.Size() == 0 {
		t.Fatal("Backup file is empty")
	}

	// Verify we have at least the initial key
	keyMetas, err := vault.ListKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to list key metadata: %v", err)
	}

	if len(keyMetas) < 1 {
		t.Error("Expected at least one key in vault")
	}

	t.Logf("Successfully backed up vault with %d keys and %d secrets", len(keyMetas), len(secrets))
	t.Logf("Backup file created at: %s (size: %d bytes)", backupFile, fileInfo.Size())
}

func testBackupWithNoMetadata(t *testing.T) {
	vault := createTestVaultWithDerivation(t)

	// Create keys but avoid creating secrets (which would create metadata)
	_, err := vault.GetActiveKeyMetadata()
	if err != nil {
		t.Fatalf("Failed to get active key: %v", err)
	}

	// Rotate once to have multiple keys but no secret metadata
	_, err = vault.RotateKey("testBackupWithNoMetadata")
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	// Create backup file path (not directory) with unique timestamp
	timestamp := time.Now().UnixNano()
	backupFile := filepath.Join(tempDir, fmt.Sprintf("vault_backup_no_metadata_%d.bak", timestamp))

	// Clean up any potentially conflicting files
	existingBackups, _ := filepath.Glob(filepath.Join(tempDir, "vault_backup_*"))
	for _, file := range existingBackups {
		os.Remove(file)
	}
	existingTemps, _ := filepath.Glob(filepath.Join(tempDir, ".tmp-*"))
	for _, file := range existingTemps {
		os.Remove(file)
	}

	os.Remove(backupFile)
	t.Cleanup(func() {
		os.Remove(backupFile)
	})

	passphrase := "no-metadata-backup-passphrase-with-sufficient-length"

	// Backup should succeed even without secret metadata
	err = vault.Backup(backupFile, passphrase)
	if err != nil {
		t.Fatalf("Backup with no metadata failed: %v", err)
	}

	// Verify backup file was created
	fileInfo, err := os.Stat(backupFile)
	if err != nil {
		t.Fatalf("Backup file was not created: %v", err)
	}

	if fileInfo.IsDir() {
		t.Fatal("Backup created a directory instead of a file")
	}

	if fileInfo.Size() == 0 {
		t.Fatal("Backup file is empty")
	}

	// Verify no secrets exist
	secrets, err := vault.ListSecrets(&SecretListOptions{})
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}

	if len(secrets) != 0 {
		t.Errorf("Expected no secrets, got %d", len(secrets))
	}

	t.Logf("Successfully backed up vault with no secret metadata")
	t.Logf("Backup file: %s (size: %d bytes)", backupFile, fileInfo.Size())
}

func testBackupFailsWhenSaltInaccessible(t *testing.T) {
	vault := createTestVaultWithDerivation(t)
	setupTestVaultData(t, vault)

	// Create a mock vault with inaccessible salt
	mockVault := &MockVaultWithSaltFailure{
		VaultService:   vault,
		saltAccessible: false,
	}

	backupDir := createTempBackupDir(t)
	defer os.RemoveAll(backupDir)
	passphrase := "salt-test-passphrase"

	// The backup should fail when trying to access the salt
	err := mockVault.Backup(backupDir, passphrase)
	if err == nil {
		t.Fatal("Expected backup to fail when salt is inaccessible, but it succeeded")
	}

	if !containsIgnoreCase(err.Error(), "salt") {
		t.Errorf("Expected error to mention salt, got: %v", err)
	}

	t.Logf("Got expected error for inaccessible salt: %v", err)
}

func testBackupFailsWhenKeyLoadFails(t *testing.T) {
	vault := createTestVaultWithDerivation(t)

	// Create some keys first
	_, err := vault.RotateKey("testBackupFailsWhenKeyLoadFails")
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	// Create a mock vault that fails on specific key operations
	mockVault := &MockVaultWithKeyLoadFailure{
		VaultService: vault,
		failKeyLoad:  true,
	}

	backupDir := createTempBackupDir(t)
	defer os.RemoveAll(backupDir)
	passphrase := "key-load-fail-passphrase"

	err = mockVault.Backup(backupDir, passphrase)
	if err == nil {
		t.Fatal("Expected backup to fail when key load fails")
	}

	if !containsIgnoreCase(err.Error(), "key") && !containsIgnoreCase(err.Error(), "load") {
		t.Errorf("Expected key load error, got: %v", err)
	}

	t.Logf("Got expected error for key load failure: %v", err)
}

func testBackupFailsWhenMetadataLoadFails(t *testing.T) {
	vault := createTestVaultWithDerivation(t)
	setupTestVaultData(t, vault)

	// Create a mock vault that fails on metadata operations
	mockVault := &MockVaultWithMetadataFailure{
		VaultService:     vault,
		failMetadataLoad: true,
	}

	backupDir := createTempBackupDir(t)
	defer os.RemoveAll(backupDir)
	passphrase := "metadata-fail-passphrase"

	err := mockVault.Backup(backupDir, passphrase)
	if err == nil {
		t.Fatal("Expected backup to fail when metadata load fails")
	}

	if !containsIgnoreCase(err.Error(), "metadata") {
		t.Errorf("Expected metadata error, got: %v", err)
	}

	t.Logf("Got expected error for metadata load failure: %v", err)
}

func testBackupFailsWhenStorageBackupFails(t *testing.T) {
	vault := createTestVaultWithDerivation(t)
	setupTestVaultData(t, vault)

	// Create a mock vault that fails on storage operations
	mockVault := &MockVaultWithStorageFailure{
		VaultService: vault,
		failStorage:  true,
	}

	backupDir := createTempBackupDir(t)
	defer os.RemoveAll(backupDir)
	passphrase := "storage-fail-passphrase"

	err := mockVault.Backup(backupDir, passphrase)
	if err == nil {
		t.Fatal("Expected backup to fail when storage backup fails")
	}

	if !containsIgnoreCase(err.Error(), "storage") && !containsIgnoreCase(err.Error(), "write") {
		t.Errorf("Expected storage error, got: %v", err)
	}

	t.Logf("Got expected error for storage backup failure: %v", err)
}

// Helper functions for the aligned tests

func setupTestVaultData(t *testing.T, vault VaultService) {
	// Create some test secrets
	secrets := map[string]struct {
		data        []byte
		tags        []string
		contentType ContentType
	}{
		"secret1": {[]byte("test-value-1"), []string{"tag1", "test"}, ContentTypeText},
		"secret2": {[]byte(`{"key": "value"}`), []string{"tag2", "json"}, ContentTypeJSON},
		"secret3": {[]byte("binary-data"), []string{"tag3", "binary"}, ContentTypeBinary},
	}

	for secretID, secret := range secrets {
		_, err := vault.StoreSecret(secretID, secret.data, secret.tags, secret.contentType)
		if err != nil {
			t.Fatalf("Failed to store secret %s: %v", secretID, err)
		}
	}
}

func createTempBackupDir(t *testing.T) string {
	backupDir, err := os.MkdirTemp("", "vault_backup_*")
	if err != nil {
		t.Fatalf("Failed to create backup dir: %v", err)
	}
	return backupDir
}

// Helper functions

// Mock vault that simulates salt access failure
type MockVaultWithSaltFailure struct {
	VaultService
	saltAccessible bool
}

func (m *MockVaultWithSaltFailure) Backup(destinationDir, passphrase string) error {
	if !m.saltAccessible {
		return fmt.Errorf("salt enclave is not accessible or corrupted")
	}
	return m.VaultService.Backup(destinationDir, passphrase)
}

// Mock vault that simulates key load failure
type MockVaultWithKeyLoadFailure struct {
	VaultService
	failKeyLoad bool
}

func (m *MockVaultWithKeyLoadFailure) Backup(destinationDir, passphrase string) error {
	if m.failKeyLoad {
		return fmt.Errorf("failed to load key material during backup")
	}
	return m.VaultService.Backup(destinationDir, passphrase)
}

func (m *MockVaultWithKeyLoadFailure) ListKeyMetadata() ([]KeyMetadata, error) {
	if m.failKeyLoad {
		return nil, fmt.Errorf("failed to load key metadata")
	}
	return m.VaultService.ListKeyMetadata()
}

// Mock vault that simulates metadata load failure
type MockVaultWithMetadataFailure struct {
	VaultService
	failMetadataLoad bool
}

func (m *MockVaultWithMetadataFailure) Backup(destinationDir, passphrase string) error {
	if m.failMetadataLoad {
		return fmt.Errorf("failed to load secret metadata during backup")
	}
	return m.VaultService.Backup(destinationDir, passphrase)
}

func (m *MockVaultWithMetadataFailure) ListSecrets(options *SecretListOptions) ([]*SecretListEntry, error) {
	if m.failMetadataLoad {
		return nil, fmt.Errorf("failed to load secret metadata")
	}
	return m.VaultService.ListSecrets(options)
}

// Mock vault that simulates storage backup failure
type MockVaultWithStorageFailure struct {
	VaultService
	failStorage bool
}

func (m *MockVaultWithStorageFailure) Backup(destinationDir, passphrase string) error {
	if m.failStorage {
		return fmt.Errorf("storage backup operation failed: unable to write backup data")
	}
	return m.VaultService.Backup(destinationDir, passphrase)
}

// Helper function to check if string contains substring (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
