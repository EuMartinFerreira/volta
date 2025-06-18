package persist

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Store implements the Store interface using MinIO as the backend with multitenancy.
// S3 Object Structure (with multitenancy):
// This structure outlines how tenant data is organized within the specified S3 bucket, facilitating
// data isolation and management of backups for each tenant.
//
// bucket/
// ├── [keyPrefix/]tenant1/
// │   ├── vault.meta          # Vault metadata (encrypted keys + key metadata) for tenant1
// │   ├── vault.salt          # Key derivation salt for tenant1
// │   ├── secrets.meta        # All secrets + secret metadata (encrypted) for tenant1
// │   └── backups/
// │       ├── backup_20240101_120000.vault  # Backup file for tenant1 dated 2024-01-01
// │       └── backup_20240102_130000.vault  # Backup file for tenant1 dated 2024-01-02
// ├── [keyPrefix/]tenant2/
// │   ├── vault.meta          # Vault metadata for tenant2
// │   ├── vault.salt          # Key derivation salt for tenant2
// │   ├── secrets.meta        # All secrets + secret metadata for tenant2
// │   └── backups/
// │       ├── backup_20240101_120000.vault  # Backup file for tenant2 dated 2024-01-01
// │       └── backup_20240102_130000.vault  # Backup file for tenant2 dated 2024-01-02
// └── [keyPrefix/]default/
// ├── vault.meta          # Vault metadata for default tenant
// ├── vault.salt          # Key derivation salt for default tenant
// ├── secrets.meta        # All secrets + secret metadata for default tenant
// └── backups/
// ├── backup_20240101_120000.vault  # Backup file for default tenant dated 2024-01-01
// └── backup_20240102_130000.vault  # Backup file for default tenant dated 2024-01-02
type S3Store struct {
	// client is the MinIO client used to interact with the MinIO server.
	client *minio.Client

	// bucket is the name of the S3 bucket used to store tenant data and backups.
	bucket string

	// keyPrefix is an optional prefix for the keys in the bucket, allowing for namespace separation
	// if multiple applications use the same bucket.
	keyPrefix string

	// tenantID uniquely identifies the tenant whose data is being stored. This is used to correctly
	// route requests and ensure data isolation between different tenants.
	tenantID string

	// ctx is the context that is used for cancellation and timeout control for operations
	// related to this S3Store instance.
	ctx context.Context

	// ctxCancel is the cancel function associated with the context. This can be called
	// to cancel any ongoing operations tied to the context.
	ctxCancel context.CancelFunc
}

// NewS3Store initializes a new S3Store instance using the provided S3 configuration
// and tenant ID. It establishes a connection to a MinIO server and ensures that the
// specified bucket exists. If no tenant ID is provided, it defaults to "default".
//
// Parameters:
//   - config (S3Config): Configuration structure containing:
//   - Endpoint (string): The endpoint URL for the MinIO server.
//   - AccessKeyID (string): The access key ID for authentication.
//   - SecretAccessKey (string): The secret access key for authentication.
//   - UseSSL (bool): Indicates whether to use SSL for the connection.
//   - Region (string): The region where the MinIO server is located.
//   - Bucket (string): The name of the bucket to use.
//   - KeyPrefix (string): A prefix for keys stored in the bucket.
//   - tenantID (string): A unique identifier for the tenant. If not provided, defaults to "default".
//
// Returns:
//   - (*S3Store, error): A pointer to an S3Store instance if successful, or an error in case of failure.
//
// Errors:
//   - Returns an error if the tenant ID is invalid, if the MinIO client fails to initialize,
//     if the bucket does not exist, or if vault configuration initialization fails.
func NewS3Store(config S3Config, tenantID string) (*S3Store, error) {
	if tenantID == "" {
		tenantID = "default"
	}

	// Validate tenant ID (basic security check)
	if err := validateTenantID(tenantID); err != nil {
		return nil, fmt.Errorf("invalid tenant ID: %w", err)
	}

	// Create MinIO client
	client, err := minio.New(config.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(config.AccessKeyID, config.SecretAccessKey, ""),
		Secure: config.UseSSL,
		Region: config.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create MinIO client: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	store := &S3Store{
		client:    client,
		bucket:    config.Bucket,
		keyPrefix: config.KeyPrefix,
		tenantID:  tenantID,
		ctx:       ctx,
		ctxCancel: cancel,
	}

	// Ensure bucket exists
	if err = store.ensureBucket(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to ensure bucket exists: %w", err)
	}

	// Ensure bucket exists
	if err = store.ensureBucket(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to ensure bucket exists: %w", err)
	}

	// Initialize vault config (similar to FileSystemStore)
	if err = store.initializeVaultConfig(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize vault config: %w", err)
	}

	return store, nil
}

// NewS3StoreFromConfig initializes a new S3Store instance from the given StoreConfig.
// It validates the store type and unmarshals the configuration.
//
// Parameters:
//   - config: Configuration parameters for the storage backend.
//   - tenantID: The ID representing the tenant using the store.
//
// Returns:
//   - A pointer to the newly created S3Store if successful, or an error.
func NewS3StoreFromConfig(config StoreConfig, tenantID string) (*S3Store, error) {
	if config.Type != StoreTypeS3 {
		return nil, fmt.Errorf("invalid store type for MinIO: %s", config.Type)
	}

	// Parse the config map into S3Config
	configBytes, err := json.Marshal(config.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var s3Config S3Config
	if err = json.Unmarshal(configBytes, &s3Config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal S3 config: %w", err)
	}

	return NewS3Store(s3Config, tenantID)
}

// S3Config contains the configuration required to connect to S3 (MinIO).
type S3Config struct {
	Endpoint        string // The endpoint for the S3 service.
	AccessKeyID     string // The Access Key ID for accessing the S3 service.
	SecretAccessKey string // The Secret Access Key for accessing the S3 service.
	Bucket          string // The S3 bucket to use.
	KeyPrefix       string // The prefix for keys stored in the S3 bucket.
	UseSSL          bool   // Whether to use SSL for the connection.
	Region          string // The region of the S3 bucket.
}

func (s3s *S3Store) initializeVaultConfig() error {
	objectName := s3s.buildTenantPath("vault.config")

	// Check if config already exists
	_, err := s3s.client.StatObject(s3s.ctx, s3s.bucket, objectName, minio.StatObjectOptions{})
	if err != nil {
		// Check if it's a not found error
		if minioErr := minio.ToErrorResponse(err); minioErr.Code == "NoSuchKey" {
			// Config doesn't exist, create it
			config := VaultConfig{
				Version:    "1.0.0",
				TenantID:   s3s.tenantID,
				CreatedAt:  time.Now().UTC(),
				LastAccess: time.Now().UTC(),
				Structure:  "v1", // Structure version for migrations
			}

			data, err := json.MarshalIndent(config, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal vault config: %w", err)
			}

			_, err = s3s.client.PutObject(
				s3s.ctx,
				s3s.bucket,
				objectName,
				bytes.NewReader(data),
				int64(len(data)),
				minio.PutObjectOptions{
					ContentType: "application/json",
					UserMetadata: map[string]string{
						"vault-config":      "true",
						"data-type":         "vault-config",
						"tenant-id":         s3s.tenantID,
						"version":           config.Version,
						"structure-version": config.Structure,
						"created-at":        config.CreatedAt.Format(time.RFC3339),
					},
				},
			)
			if err != nil {
				return fmt.Errorf("failed to create vault config: %w", err)
			}
		} else {
			return fmt.Errorf("failed to check vault config: %w", err)
		}
	}

	return nil
}

// ListTenants returns all tenant IDs that have vaults in the bucket
func (s3s *S3Store) ListTenants() ([]string, error) {
	// Build base prefix for listing
	var basePrefix string
	if s3s.keyPrefix != "" {
		basePrefix = s3s.keyPrefix + "/"
	}

	// List all objects to find tenant directories
	objectCh := s3s.client.ListObjects(s3s.ctx, s3s.bucket, minio.ListObjectsOptions{
		Prefix:    basePrefix,
		Recursive: false,
	})

	tenantSet := make(map[string]bool)
	for object := range objectCh {
		if object.Err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", object.Err)
		}

		// Extract tenant ID from object path
		relativePath := strings.TrimPrefix(object.Key, basePrefix)
		parts := strings.Split(relativePath, "/")
		if len(parts) > 0 && parts[0] != "" {
			tenantSet[parts[0]] = true
		}
	}

	// Convert to sorted slice
	var tenants []string
	for tenant := range tenantSet {
		tenants = append(tenants, tenant)
	}
	sort.Strings(tenants)

	return tenants, nil
}

// DeleteTenant removes all data for a tenant (USE WITH EXTREME CAUTION)
func (s3s *S3Store) DeleteTenant(tenantID string) error {
	if err := validateTenantID(tenantID); err != nil {
		return fmt.Errorf("invalid tenant ID: %w", err)
	}

	// Safety check - don't delete if it's the current tenant
	if tenantID == s3s.tenantID {
		return fmt.Errorf("cannot delete current tenant")
	}

	// Build tenant prefix
	tenantPrefix := s3s.buildTenantPath("", tenantID) + "/"

	// List all objects for this tenant
	objectCh := s3s.client.ListObjects(s3s.ctx, s3s.bucket, minio.ListObjectsOptions{
		Prefix:    tenantPrefix,
		Recursive: true,
	})

	// Collect object names to delete
	var objectNames []string
	for object := range objectCh {
		if object.Err != nil {
			return fmt.Errorf("failed to list tenant objects: %w", object.Err)
		}
		objectNames = append(objectNames, object.Key)
	}

	// Delete objects in batches
	for _, objectName := range objectNames {
		err := s3s.client.RemoveObject(s3s.ctx, s3s.bucket, objectName, minio.RemoveObjectOptions{})
		if err != nil {
			return fmt.Errorf("failed to delete object %s: %w", objectName, err)
		}
	}

	return nil
}

func (s3s *S3Store) SaveMetadata(encryptedMetadata []byte) error {
	objectName := s3s.buildTenantPath("vault.meta")

	_, err := s3s.client.PutObject(
		s3s.ctx,
		s3s.bucket,
		objectName,
		bytes.NewReader(encryptedMetadata),
		int64(len(encryptedMetadata)),
		minio.PutObjectOptions{
			ContentType: "application/octet-stream",
			UserMetadata: map[string]string{
				"vault-metadata": "true",
				"data-type":      "vault-metadata",
				"tenant-id":      s3s.tenantID,
				"updated-at":     time.Now().UTC().Format(time.RFC3339),
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to save vault metadata: %w", err)
	}

	return nil
}

func (s3s *S3Store) LoadMetadata() ([]byte, error) {
	objectName := s3s.buildTenantPath("vault.meta")

	object, err := s3s.client.GetObject(s3s.ctx, s3s.bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get vault metadata: %w", err)
	}
	defer object.Close()

	data, err := io.ReadAll(object)
	if err != nil {
		// Check if it's a NoSuchKey error for better error message
		if minioErr := minio.ToErrorResponse(err); minioErr.Code == "NoSuchKey" {
			return nil, fmt.Errorf("vault metadata not found for tenant %s", s3s.tenantID)
		}
		return nil, fmt.Errorf("failed to read vault metadata: %w", err)
	}

	return data, nil
}

func (s3s *S3Store) MetadataExists() (bool, error) {
	objectName := s3s.buildTenantPath("vault.meta")

	_, err := s3s.client.StatObject(s3s.ctx, s3s.bucket, objectName, minio.StatObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return false, nil
		}
		return false, fmt.Errorf("failed to check vault metadata existence: %w", err)
	}

	return true, nil
}

// Salt operations
func (s3s *S3Store) SaveSalt(saltData []byte) error {
	objectName := s3s.buildTenantPath("vault.salt")

	_, err := s3s.client.PutObject(
		s3s.ctx,
		s3s.bucket,
		objectName,
		bytes.NewReader(saltData),
		int64(len(saltData)),
		minio.PutObjectOptions{
			ContentType: "application/octet-stream",
			UserMetadata: map[string]string{
				"vault-salt": "true",
				"data-type":  "salt",
				"tenant-id":  s3s.tenantID,
				"created-at": time.Now().UTC().Format(time.RFC3339),
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to save salt: %w", err)
	}

	return nil
}

func (s3s *S3Store) LoadSalt() ([]byte, error) {
	objectName := s3s.buildTenantPath("vault.salt")

	object, err := s3s.client.GetObject(s3s.ctx, s3s.bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get salt: %w", err)
	}
	defer object.Close()

	data, err := io.ReadAll(object)
	if err != nil {
		// Check if it's a NoSuchKey error
		if minioErr := minio.ToErrorResponse(err); minioErr.Code == "NoSuchKey" {
			return nil, fmt.Errorf("derivation salt not found for tenant %s", s3s.tenantID)
		}
		return nil, fmt.Errorf("failed to read salt: %w", err)
	}

	return data, nil
}

func (s3s *S3Store) SaltExists() (bool, error) {
	objectName := s3s.buildTenantPath("vault.salt")

	_, err := s3s.client.StatObject(s3s.ctx, s3s.bucket, objectName, minio.StatObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return false, nil
		}
		return false, fmt.Errorf("failed to check salt existence: %w", err)
	}

	return true, nil
}

// Secrets operations - unified secrets data (all secrets + metadata in one object)
func (s3s *S3Store) SaveSecretsData(encryptedSecretsData []byte) error {
	objectName := s3s.buildTenantPath("secrets.meta")

	_, err := s3s.client.PutObject(
		s3s.ctx,
		s3s.bucket,
		objectName,
		bytes.NewReader(encryptedSecretsData),
		int64(len(encryptedSecretsData)),
		minio.PutObjectOptions{
			ContentType: "application/octet-stream",
			UserMetadata: map[string]string{
				"vault-secrets": "true",
				"data-type":     "secrets-data",
				"tenant-id":     s3s.tenantID,
				"updated-at":    time.Now().UTC().Format(time.RFC3339),
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to save secrets data: %w", err)
	}

	return nil
}

func (s3s *S3Store) LoadSecretsData() ([]byte, error) {
	objectName := s3s.buildTenantPath("secrets.meta")

	object, err := s3s.client.GetObject(s3s.ctx, s3s.bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets data: %w", err)
	}
	defer object.Close()

	data, err := io.ReadAll(object)
	if err != nil {
		// Check if it's a NoSuchKey error
		if minioErr := minio.ToErrorResponse(err); minioErr.Code == "NoSuchKey" {
			return nil, fmt.Errorf("secrets data not found for tenant %s", s3s.tenantID)
		}
		return nil, fmt.Errorf("failed to read secrets data: %w", err)
	}

	return data, nil
}

func (s3s *S3Store) SecretsDataExists() (bool, error) {
	objectName := s3s.buildTenantPath("secrets.meta")

	_, err := s3s.client.StatObject(s3s.ctx, s3s.bucket, objectName, minio.StatObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return false, nil
		}
		return false, fmt.Errorf("failed to check secrets data existence: %w", err)
	}

	return true, nil
}

// Backup operations
func (s3s *S3Store) SaveBackup(backupPath string, container *BackupContainer) error {
	// Validate backup path
	if backupPath == "" {
		return fmt.Errorf("backup path cannot be empty")
	}

	// Add tenant ID to backup container metadata if not already set
	if container.TenantID == "" {
		container.TenantID = s3s.tenantID
	}

	// Marshal container to JSON
	containerData, err := json.MarshalIndent(container, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup container: %w", err)
	}

	// Build S3 object name
	objectName := s3s.buildTenantPath("backups", backupPath+".vault")

	// Store backup container as single object
	_, err = s3s.client.PutObject(
		s3s.ctx,
		s3s.bucket,
		objectName,
		bytes.NewReader(containerData),
		int64(len(containerData)),
		minio.PutObjectOptions{
			ContentType: "application/json",
			UserMetadata: map[string]string{
				"vault-backup":      "true",
				"backup-id":         container.BackupID,
				"backup-version":    container.BackupVersion,
				"vault-version":     container.VaultVersion,
				"tenant-id":         container.TenantID,
				"backup-timestamp":  container.BackupTimestamp.Format(time.RFC3339),
				"encryption-method": container.EncryptionMethod,
				"checksum":          container.Checksum,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to save backup container: %w", err)
	}

	return nil
}

func (s3s *S3Store) RestoreBackup(backupPath string) (*BackupContainer, error) {
	// Validate backup path
	if backupPath == "" {
		return nil, fmt.Errorf("backup path cannot be empty")
	}

	// Build object name
	objectName := s3s.buildTenantPath("backups", backupPath+".vault")

	// Get the backup object
	object, err := s3s.client.GetObject(s3s.ctx, s3s.bucket, objectName, minio.GetObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, fmt.Errorf("backup '%s' not found for tenant %s", backupPath, s3s.tenantID)
		}
		return nil, fmt.Errorf("failed to get backup: %w", err)
	}
	defer object.Close()

	// Read container data
	containerData, err := io.ReadAll(object)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup container: %w", err)
	}

	// Unmarshal container
	var container BackupContainer
	if err := json.Unmarshal(containerData, &container); err != nil {
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
	if container.TenantID != "" && container.TenantID != s3s.tenantID {
		fmt.Printf("Warning: Restoring backup from tenant %s to tenant %s\n",
			container.TenantID, s3s.tenantID)
	}

	return &container, nil
}

func (s3s *S3Store) DeleteBackup(backupID string) error {
	// For S3 implementation, we need to find the backup by ID
	// This requires listing backups and finding the one with matching ID
	backups, err := s3s.ListBackups()
	if err != nil {
		return fmt.Errorf("failed to list backups for deletion: %w", err)
	}

	var backupPath string
	for _, backup := range backups {
		if backup.BackupID == backupID {
			// Extract path from backup (this assumes we can derive path from backup info)
			// For simplicity, we'll use the backup ID as the path
			backupPath = backupID
			break
		}
	}

	if backupPath == "" {
		return fmt.Errorf("backup %s not found for tenant %s", backupID, s3s.tenantID)
	}

	// Build object name
	objectName := s3s.buildTenantPath("backups", backupPath+".vault")

	// Delete the backup object
	err = s3s.client.RemoveObject(s3s.ctx, s3s.bucket, objectName, minio.RemoveObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).Code != "NoSuchKey" {
			return fmt.Errorf("failed to delete backup '%s': %w", backupID, err)
		}
	}

	return nil
}

func (s3s *S3Store) ListBackups() ([]BackupInfo, error) {
	// Build prefix for listing tenant's backups
	prefix := s3s.buildTenantPath("backups") + "/"

	// List objects with backup prefix
	objectCh := s3s.client.ListObjects(s3s.ctx, s3s.bucket, minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	})

	var backups []BackupInfo

	for object := range objectCh {
		if object.Err != nil {
			return nil, fmt.Errorf("failed to list backup objects: %w", object.Err)
		}

		// Skip directories and non-backup files
		if strings.HasSuffix(object.Key, "/") {
			continue
		}

		// Only process .vault files
		if !strings.HasSuffix(object.Key, ".vault") {
			continue
		}

		// Try to get backup info from metadata first (fast path)
		info, err := s3s.getBackupInfoFromMetadata(object)
		if err != nil {
			// If metadata approach fails, try loading the full backup (slow path)
			backupPath := strings.TrimPrefix(object.Key, prefix)
			backupPath = strings.TrimSuffix(backupPath, ".vault")

			info, err = s3s.getBackupInfoFromContent(backupPath, object.Size)
			if err != nil {
				// Create minimal info for invalid backups
				info = &BackupInfo{
					BackupID:        fmt.Sprintf("unknown-%s", backupPath),
					BackupTimestamp: object.LastModified,
					VaultVersion:    "unknown",
					BackupVersion:   "unknown",
					TenantID:        s3s.tenantID,
					FileSize:        object.Size,
					IsValid:         false,
				}
			}
		}

		// Ensure tenant ID is set
		if info.TenantID == "" {
			info.TenantID = s3s.tenantID
		}

		backups = append(backups, *info)
	}

	// Sort backups by timestamp (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].BackupTimestamp.After(backups[j].BackupTimestamp)
	})

	return backups, nil
}

// Health and utilities
func (s3s *S3Store) Ping() error {
	// For S3, test connectivity by checking if bucket exists
	exists, err := s3s.client.BucketExists(s3s.ctx, s3s.bucket)
	if err != nil {
		return fmt.Errorf("failed to ping S3: %w", err)
	}
	if !exists {
		return fmt.Errorf("bucket %s does not exist", s3s.bucket)
	}
	return nil
}

func (s3s *S3Store) Close() error {
	// Update last access time in config (similar to FileSystemStore)
	objectName := s3s.buildTenantPath("vault.config")

	// Try to load existing config
	object, err := s3s.client.GetObject(s3s.ctx, s3s.bucket, objectName, minio.GetObjectOptions{})
	if err == nil {
		defer object.Close()

		if configData, err := io.ReadAll(object); err == nil {
			var config VaultConfig
			if err := json.Unmarshal(configData, &config); err == nil {
				// Update last access time
				config.LastAccess = time.Now().UTC()

				if updatedData, err := json.MarshalIndent(config, "", "  "); err == nil {
					// Save updated config
					_, _ = s3s.client.PutObject(
						s3s.ctx,
						s3s.bucket,
						objectName,
						bytes.NewReader(updatedData),
						int64(len(updatedData)),
						minio.PutObjectOptions{
							ContentType: "application/json",
							UserMetadata: map[string]string{
								"vault-config": "true",
								"data-type":    "vault-config",
								"tenant-id":    s3s.tenantID,
								"updated-at":   time.Now().UTC().Format(time.RFC3339),
							},
						},
					)
				}
			}
		}
	}

	// Cancel context and cleanup
	if s3s.ctxCancel != nil {
		s3s.ctxCancel()
	}
	return nil
}

func (s3s *S3Store) GetType() string {
	return string(StoreTypeS3)
}

// Helper methods
func (s3s *S3Store) buildPath(components ...string) string {
	var parts []string
	if s3s.keyPrefix != "" {
		parts = append(parts, s3s.keyPrefix)
	}
	parts = append(parts, components...)
	return strings.Join(parts, "/")
}

func (s3s *S3Store) buildTenantPath(components ...string) string {
	return s3s.buildTenantPathForTenant(s3s.tenantID, components...)
}

func (s3s *S3Store) buildTenantPathForTenant(tenantID string, components ...string) string {
	var parts []string
	if s3s.keyPrefix != "" {
		parts = append(parts, s3s.keyPrefix)
	}
	parts = append(parts, tenantID)
	parts = append(parts, components...)
	return strings.Join(parts, "/")
}

func (s3s *S3Store) ensureBucket() error {
	exists, err := s3s.client.BucketExists(s3s.ctx, s3s.bucket)
	if err != nil {
		return fmt.Errorf("failed to check if bucket exists: %w", err)
	}

	if !exists {
		err = s3s.client.MakeBucket(s3s.ctx, s3s.bucket, minio.MakeBucketOptions{})
		if err != nil {
			return fmt.Errorf("failed to create bucket: %w", err)
		}
	}

	return nil
}

func (s3s *S3Store) getBackupInfoFromMetadata(object minio.ObjectInfo) (*BackupInfo, error) {
	// Extract basic info from object metadata
	backupID := object.UserMetadata["X-Amz-Meta-Backup-Id"]
	backupVersion := object.UserMetadata["X-Amz-Meta-Backup-Version"]
	vaultVersion := object.UserMetadata["X-Amz-Meta-Vault-Version"]
	encryptionMethod := object.UserMetadata["X-Amz-Meta-Encryption-Method"]
	checksumFromMeta := object.UserMetadata["X-Amz-Meta-Checksum"]
	tenantID := object.UserMetadata["X-Amz-Meta-Tenant-Id"]

	if backupID == "" || backupVersion == "" {
		return nil, fmt.Errorf("incomplete metadata")
	}

	// Parse timestamp
	var backupTimestamp time.Time
	if timestampStr := object.UserMetadata["X-Amz-Meta-Backup-Timestamp"]; timestampStr != "" {
		if parsed, err := time.Parse(time.RFC3339, timestampStr); err == nil {
			backupTimestamp = parsed
		} else {
			backupTimestamp = object.LastModified
		}
	} else {
		backupTimestamp = object.LastModified
	}

	// Use current tenant if not specified in metadata
	if tenantID == "" {
		tenantID = s3s.tenantID
	}

	return &BackupInfo{
		BackupID:         backupID,
		BackupTimestamp:  backupTimestamp,
		VaultVersion:     vaultVersion,
		BackupVersion:    backupVersion,
		EncryptionMethod: encryptionMethod,
		TenantID:         tenantID,
		FileSize:         object.Size,
		IsValid:          checksumFromMeta != "",
	}, nil
}

func (s3s *S3Store) getBackupInfoFromContent(backupPath string, fileSize int64) (*BackupInfo, error) {
	// Load the backup to get info
	container, err := s3s.RestoreBackup(backupPath)
	if err != nil {
		return nil, err
	}

	// Verify checksum
	isValid := false
	if container.Checksum != "" && container.EncryptedData != "" {
		encryptedData, err := base64.StdEncoding.DecodeString(container.EncryptedData)
		if err == nil {
			actualChecksum := s3s.calculateChecksum(encryptedData)
			isValid = actualChecksum == container.Checksum
		}
	}

	// Use current tenant if not specified in backup
	tenantID := container.TenantID
	if tenantID == "" {
		tenantID = s3s.tenantID
	}

	return &BackupInfo{
		BackupID:         container.BackupID,
		BackupTimestamp:  container.BackupTimestamp,
		VaultVersion:     container.VaultVersion,
		BackupVersion:    container.BackupVersion,
		EncryptionMethod: container.EncryptionMethod,
		TenantID:         tenantID,
		FileSize:         fileSize,
		IsValid:          isValid,
	}, nil
}

func (s3s *S3Store) calculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
