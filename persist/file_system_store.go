package persist

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"southwinds.dev/volta/internal/debug"
	"strings"
	"time"
)

const (
	FilePermissions os.FileMode = 0600
	DirPermissions  os.FileMode = 0700
)

// FileSystemStore implements Store for local filesystem with multitenancy
// vault/
// ├── tenant1/                # Tenant isolation
// │   ├── backups/            # Backup files for tenant1
// │   │   ├── backup_20240101_120000.vault
// │   │   └── backup_20240102_130000.vault
// │   ├── temp/               # Temporary operations for tenant1
// │   ├── vault.json          # Vault configuration for tenant1
// │   ├── vault.meta          # Vault metadata (encrypted keys + key metadata)
// │   ├── derivation.salt     # Key derivation salt
// │   └── secrets.meta        # All secrets + secret metadata (encrypted)
// ├── tenant2/                # Another tenant
// │   ├── backups/
// │   ├── temp/
// │   ├── vault.json
// │   ├── vault.meta
// │   ├── derivation.salt
// │   └── secrets.meta
// └── default/                # Default tenant
// ├── backups/
// ├── temp/
// ├── vault.json
// ├── vault.meta
// ├── derivation.salt
// └── secrets.meta
type FileSystemStore struct {
	basePath    string
	tenantID    string
	tenantPath  string // basePath/tenantID/
	backupsDir  string // basePath/tenantID/backups/
	tempDir     string // basePath/tenantID/temp/
	vaultConfig string // basePath/tenantID/vault.json
	vaultMeta   string // basePath/tenantID/vault.meta     - vault metadata (keys + key metadata)
	vaultSalt   string // basePath/tenantID/vault.salt     - derivation salt
	secretsMeta string // basePath/tenantID/secrets.meta   - secrets + secret metadata
}

// VaultConfig represents the vault configuration and metadata
type VaultConfig struct {
	// Version tracks the vault software/format version that created this vault
	// Used for migration support, compatibility checks, and preventing newer
	// vaults from being opened by older software versions
	// Example: "1.0.0", "2.1.3"
	Version string `json:"version"`

	// TenantID identifies which tenant owns this specific vault instance
	// Provides multi-tenant isolation, audit trails, and prevents accidental
	// cross-tenant operations during backup/restore
	// Example: "customer-123", "default", "internal-dev"
	TenantID string `json:"tenant_id"`

	// CreatedAt records when this vault was first created (immutable)
	// Used for audit trails, compliance, vault lifecycle management,
	// billing/usage tracking, and debugging
	// Set once during vault initialization and never modified
	CreatedAt time.Time `json:"created_at"`

	// LastAccess tracks the most recent vault access time
	// Updated on every vault open/close operation for usage analytics,
	// inactive vault cleanup policies, security auditing, and performance optimization
	// Used to detect unauthorized access and cache frequently used vaults
	LastAccess time.Time `json:"last_access"`

	// Structure defines the internal file/data structure format version
	// Different from Version (software) - this tracks data schema version
	// Used for schema migration, backward compatibility, data format validation,
	// and recovery procedures when vault structure changes
	// Example: "v1.2", "v2.0"
	Structure string `json:"structure_version"`

	// Description is an optional human-readable description of vault purpose
	// Used for documentation, team collaboration, administrative UI display,
	// and backup/recovery identification
	// Example: "Production secrets for customer portal", "Dev environment keys"
	Description string `json:"description,omitempty"`
}

// NewFileSystemStore initializes and returns a new instance of FileSystemStore.
// It takes a base path where the tenant's files will be stored and the tenant ID.
// If tenant ID is empty, it defaults to "default".
//
// Parameters:
//   - basePath (string): The base directory where tenant-specific data is stored.
//   - tenantID (string): The unique identifier for a tenant, used for tenant-specific paths.
//     If empty, "default" is used.
//
// Returns:
//   - (*FileSystemStore): A pointer to the newly created FileSystemStore instance.
//   - (error): An error if the tenant ID is invalid or if there are any issues
//     creating necessary directories or initializing vault configuration.
func NewFileSystemStore(basePath string, tenantID string) (*FileSystemStore, error) {
	if tenantID == "" {
		tenantID = "default"
	}

	// Validate tenant ID (basic security check)
	if err := validateTenantID(tenantID); err != nil {
		return nil, fmt.Errorf("invalid tenant ID: %w", err)
	}

	tenantPath := filepath.Join(basePath, tenantID)

	fs := &FileSystemStore{
		basePath:    basePath,
		tenantID:    tenantID,
		tenantPath:  tenantPath,
		backupsDir:  filepath.Join(tenantPath, "backups"),
		tempDir:     filepath.Join(tenantPath, "temp"),
		vaultConfig: filepath.Join(tenantPath, "vault.json"),
		vaultMeta:   filepath.Join(tenantPath, "vault.meta"),
		vaultSalt:   filepath.Join(tenantPath, "derivation.salt"),
		secretsMeta: filepath.Join(tenantPath, "secrets.meta"),
	}

	// Create necessary directories
	dirs := []string{
		fs.tenantPath,
		fs.backupsDir,
		fs.tempDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, DirPermissions); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Initialize vault config if needed
	if err := fs.initializeVaultConfig(); err != nil {
		return nil, fmt.Errorf("failed to initialize vault config: %w", err)
	}

	return fs, nil
}

// NewFileSystemStoreFromConfig creates a FileSystemStore from StoreConfig
func NewFileSystemStoreFromConfig(config StoreConfig, tenantID string) (*FileSystemStore, error) {
	basePath, ok := config.Config["base_path"].(string)
	if !ok {
		return nil, fmt.Errorf("base_path is required for filesystem store")
	}

	return NewFileSystemStore(basePath, tenantID)
}

func (fs *FileSystemStore) initializeVaultConfig() error {
	if _, err := os.Stat(fs.vaultConfig); os.IsNotExist(err) {
		config := VaultConfig{
			Version:    "1.0.0",
			TenantID:   fs.tenantID,
			CreatedAt:  time.Now(),
			LastAccess: time.Now(),
			Structure:  "v1", // Structure version for migrations
		}

		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return err
		}

		return writeSecureFile(fs.vaultConfig, data, FilePermissions)
	}
	return nil
}

// ListTenants returns all tenant IDs that have vaults in the base path
func (fs *FileSystemStore) ListTenants() ([]string, error) {
	entries, err := os.ReadDir(fs.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to read base directory: %w", err)
	}

	var tenants []string
	for _, entry := range entries {
		if entry.IsDir() {
			// Check if it's a valid tenant directory (has vault.json)
			vaultConfigPath := filepath.Join(fs.basePath, entry.Name(), "vault.json")
			if _, err := os.Stat(vaultConfigPath); err == nil {
				tenants = append(tenants, entry.Name())
			}
		}
	}

	sort.Strings(tenants)
	return tenants, nil
}

// DeleteTenant removes all data for a tenant (USE WITH EXTREME CAUTION)
func (fs *FileSystemStore) DeleteTenant(tenantID string) error {
	if err := validateTenantID(tenantID); err != nil {
		return fmt.Errorf("invalid tenant ID: %w", err)
	}

	tenantPath := filepath.Join(fs.basePath, tenantID)

	// Safety check - don't delete if it's the current tenant
	if tenantID == fs.tenantID {
		return fmt.Errorf("cannot delete current tenant")
	}

	if err := os.RemoveAll(tenantPath); err != nil {
		return fmt.Errorf("failed to delete tenant data: %w", err)
	}

	return nil
}

// Vault metadata operations (keys + key metadata)
func (fs *FileSystemStore) SaveMetadata(encryptedMetadata []byte) error {
	return writeSecureFile(fs.vaultMeta, encryptedMetadata, FilePermissions)
}

func (fs *FileSystemStore) LoadMetadata() ([]byte, error) {
	data, err := os.ReadFile(fs.vaultMeta)
	if err != nil {
		if os.IsNotExist(err) {
			// Return the original error so os.IsNotExist still works
			return nil, err
		}
		return nil, fmt.Errorf("failed to load vault metadata: %w", err)
	}
	return data, nil
}

func (fs *FileSystemStore) MetadataExists() (bool, error) {
	return fileExists(fs.vaultMeta)
}

// Salt operations
func (fs *FileSystemStore) SaveSalt(saltData []byte) error {
	return writeSecureFile(fs.vaultSalt, saltData, FilePermissions)
}

func (fs *FileSystemStore) LoadSalt() ([]byte, error) {
	data, err := os.ReadFile(fs.vaultSalt)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("derivation salt not found")
		}
		return nil, fmt.Errorf("failed to load derivation salt: %w", err)
	}
	return data, nil
}

func (fs *FileSystemStore) SaltExists() (bool, error) {
	return fileExists(fs.vaultSalt)
}

// Secrets operations
func (fs *FileSystemStore) SaveSecretsData(encryptedSecretsData []byte) error {
	return writeSecureFile(fs.secretsMeta, encryptedSecretsData, FilePermissions)
}

func (fs *FileSystemStore) LoadSecretsData() ([]byte, error) {
	debug.Print("LoadSecretsData: Reading from %s (tenant: %s)\n", fs.secretsMeta, fs.tenantID)

	data, err := os.ReadFile(fs.secretsMeta)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to load secrets data: %w", err)
	}

	debug.Print("LoadSecretsData: Read %d bytes for tenant %s, first 32: %x\n",
		len(data), fs.tenantID, data[:min(32, len(data))])
	return data, nil
}

func (fs *FileSystemStore) SecretsDataExists() (bool, error) {
	return fileExists(fs.secretsMeta)
}

// Backup operations
func (fs *FileSystemStore) SaveBackup(backupPath string, container *BackupContainer) error {
	// If backupPath is just a filename, put it in the tenant's backup directory
	if !filepath.IsAbs(backupPath) && !strings.Contains(backupPath, string(os.PathSeparator)) {
		backupPath = filepath.Join(fs.backupsDir, backupPath)
	}

	// Ensure backup directory exists
	backupDir := filepath.Dir(backupPath)
	if err := os.MkdirAll(backupDir, DirPermissions); err != nil {
		return fmt.Errorf("failed to create backup directory %s: %w", backupDir, err)
	}

	// Add tenant ID to backup container metadata if not already set
	if container.TenantID == "" {
		container.TenantID = fs.tenantID
	}

	// Marshal container to JSON
	containerData, err := json.MarshalIndent(container, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup container: %w", err)
	}

	// Write to file with secure permissions
	if err = writeSecureFile(backupPath, containerData, FilePermissions); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	return nil
}

func (fs *FileSystemStore) RestoreBackup(backupPath string) (*BackupContainer, error) {
	// If backupPath is just a filename, look in the tenant's backup directory
	if !filepath.IsAbs(backupPath) && !strings.Contains(backupPath, string(os.PathSeparator)) {
		backupPath = filepath.Join(fs.backupsDir, backupPath)
	}

	// Verify backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("backup file %s does not exist", backupPath)
	}

	// Read backup file
	containerData, err := readSecureFile(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup file: %w", err)
	}

	// Unmarshal container
	var container BackupContainer
	if err = json.Unmarshal(containerData, &container); err != nil {
		return nil, fmt.Errorf("failed to parse backup container: %w", err)
	}

	// Basic validation
	if container.BackupID == "" {
		return nil, fmt.Errorf("invalid backup: missing backup ID")
	}

	if container.BackupVersion == "" {
		return nil, fmt.Errorf("invalid backup: missing backup version")
	}

	if container.EncryptedData == "" {
		return nil, fmt.Errorf("invalid backup: missing encrypted data")
	}

	// Warn if backup is from a different tenant
	if container.TenantID != "" && container.TenantID != fs.tenantID {
		debug.Print("Warning: Restoring backup from tenant %s to tenant %s\n",
			container.TenantID, fs.tenantID)
	}

	return &container, nil
}

func (fs *FileSystemStore) DeleteBackup(backupID string) error {
	// For filesystem implementation, we need to find the backup file by ID
	backupPath := filepath.Join(fs.backupsDir, backupID+".vault")

	if err := os.Remove(backupPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("backup %s does not exist", backupID)
		}
		return fmt.Errorf("failed to delete backup %s: %w", backupID, err)
	}
	return nil
}

func (fs *FileSystemStore) ListBackups() ([]BackupInfo, error) {
	if _, err := os.Stat(fs.backupsDir); os.IsNotExist(err) {
		return []BackupInfo{}, nil // Directory doesn't exist, return empty list
	}

	entries, err := os.ReadDir(fs.backupsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}

	var backups []BackupInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Only process .vault files
		if !strings.HasSuffix(entry.Name(), ".vault") {
			continue
		}

		backupPath := filepath.Join(fs.backupsDir, entry.Name())

		// Get file info
		fileInfo, err := entry.Info()
		if err != nil {
			continue // Skip files we can't stat
		}

		// Try to load backup info
		container, err := fs.RestoreBackup(backupPath)
		if err != nil {
			// If we can't load it, create minimal info
			backups = append(backups, BackupInfo{
				BackupID:        fmt.Sprintf("unknown-%s", entry.Name()),
				BackupTimestamp: fileInfo.ModTime(),
				VaultVersion:    "unknown",
				BackupVersion:   "unknown",
				TenantID:        fs.tenantID,
				FileSize:        fileInfo.Size(),
				IsValid:         false,
			})
			continue
		}

		// Verify checksum
		encryptedData, err := base64.StdEncoding.DecodeString(container.EncryptedData)
		isValid := false
		if err == nil {
			actualChecksum := fs.calculateChecksum(encryptedData)
			isValid = actualChecksum == container.Checksum
		}

		backupInfo := BackupInfo{
			BackupID:         container.BackupID,
			BackupTimestamp:  container.BackupTimestamp,
			VaultVersion:     container.VaultVersion,
			BackupVersion:    container.BackupVersion,
			EncryptionMethod: container.EncryptionMethod,
			TenantID:         container.TenantID,
			FileSize:         fileInfo.Size(),
			IsValid:          isValid,
		}

		// Use current tenant if backup doesn't have tenant info
		if backupInfo.TenantID == "" {
			backupInfo.TenantID = fs.tenantID
		}

		backups = append(backups, backupInfo)
	}

	// Sort by timestamp (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].BackupTimestamp.After(backups[j].BackupTimestamp)
	})

	return backups, nil
}

func (fs *FileSystemStore) GetType() string {
	return string(StoreTypeFileSystem)
}

// Health and utilities
func (fs *FileSystemStore) Ping() error {
	// For filesystem, check if tenant path is accessible
	_, err := os.Stat(fs.tenantPath)
	return err
}

func (fs *FileSystemStore) Close() error {
	// Update last access time in config
	if configData, err := os.ReadFile(fs.vaultConfig); err == nil {
		var config VaultConfig
		if err := json.Unmarshal(configData, &config); err == nil {
			config.LastAccess = time.Now()
			if updatedData, err := json.MarshalIndent(config, "", "  "); err == nil {
				_ = writeSecureFile(fs.vaultConfig, updatedData, FilePermissions)
			}
		}
	}
	return nil
}

func (fs *FileSystemStore) calculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Helper functions (unchanged)
func writeSecureFile(path string, data []byte, perm os.FileMode) error {
	// Create a temporary file in the same directory
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Write data to the temp file
	if _, err = tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to write to temp file: %w", err)
	}

	// Sync to ensure data is written to disk
	if err = tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	// Close the file
	if err = tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Set permissions before rename
	if err = os.Chmod(tmpPath, perm); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Atomic rename
	if err = os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func readSecureFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return data, nil
}
