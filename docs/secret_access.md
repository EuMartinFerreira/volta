# Secret Access: Usage Priority & Security Guidelines

## Table of Contents
1. [Overview](#overview)
2. [Method Priority Ranking](#method-priority-ranking)
3. [Security Best Practices](#security-best-practices)
4. [Common Usage Patterns](#common-usage-patterns)
5. [Anti-Patterns & Security Pitfalls](#anti-patterns--security-pitfalls)
6. [Performance Considerations](#performance-considerations)
7. [Error Handling](#error-handling)
8. [Testing Guidelines](#testing-guidelines)
9. [Monitoring & Logging](#monitoring--logging)
10. [Migration Guide](#migration-guide)

## Overview

Volta provides multiple methods for accessing secrets, each designed for different use cases with varying security guarantees. 
This document provides authoritative guidance on choosing the right method and implementing secure secret handling practices.

### Security Philosophy

1. **Minimize Exposure Time**: Secrets should exist in memory for the shortest possible duration
2. **Automatic Cleanup**: Prefer methods that guarantee cleanup without manual intervention
3. **Fail-Safe Defaults**: Choose methods that are secure even when used incorrectly
4. **Defense in Depth**: Multiple layers of protection against secret leakage

## Method Priority Ranking

### 🟢 **TIER 1: RECOMMENDED (Use These First)**

#### 1. `UseSecret(secretID, func([]byte) error)`
**Security Level**: ⭐⭐⭐⭐⭐ (Highest)

```go
// ✅ BEST PRACTICE
err := vault.UseSecret("api/token", func(token []byte) error {
    req.Header.Set("Authorization", "Bearer "+string(token))
    return client.Do(req)
})
```

**Why Use This:**
- Automatic memory cleanup guaranteed
- Panic-safe cleanup
- Minimal exposure window
- Cannot accidentally retain references
- Zero configuration required

**When to Use:**
- Single operations with secrets
- API calls requiring authentication
- Database connections
- File encryption/decryption
- 95% of secret usage scenarios

#### 2. `UseSecretString(secretID, func(string) error)`
**Security Level**: ⭐⭐⭐⭐⭐ (Highest)

```go
// ✅ BEST PRACTICE for string secrets
err := vault.UseSecretString("db/password", func(password string) error {
    dsn := fmt.Sprintf("user=app password=%s host=localhost", password)
    db, err := sql.Open("postgres", dsn)
    if err != nil {
        return err
    }
    defer db.Close()
    return db.Ping()
})
```

**Why Use This:**
- Same security as `UseSecret` but string-optimized
- Perfect for passwords, tokens, URLs
- Automatic string memory clearing
- Type-safe string handling

**When to Use:**
- Password-based authentication
- API keys and tokens
- Configuration strings with secrets
- Any naturally string-based secret

### 🟡 **TIER 2: CONDITIONAL (Use When Tier 1 Insufficient)**

#### 3. `UseSecretWithTimeout(secretID, timeout, func([]byte) error)`
**Security Level**: ⭐⭐⭐⭐ (High)

```go
// ✅ GOOD - when you need timeout protection
err := vault.UseSecretWithTimeout("slow/api-key", 30*time.Second, func(key []byte) error {
    return performSlowNetworkOperation(key)
})
```

**Why Use This:**
- Same security as `UseSecret` + timeout protection
- Prevents hung operations from retaining secrets
- Automatic cleanup on timeout

**When to Use:**
- Network operations that might hang
- External service calls with unknown latency
- Operations where timeout is critical for security

#### 4. `UseSecretWithContext(ctx, secretID, func([]byte) error)`
**Security Level**: ⭐⭐⭐⭐ (High)

```go
// ✅ GOOD - for context integration
func handleRequest(ctx context.Context, req *http.Request) error {
    return vault.UseSecretWithContext(ctx, "auth/key", func(key []byte) error {
        return authenticateRequest(ctx, req, key)
    })
}
```

**Why Use This:**
- Same security as `UseSecret` + context integration
- Automatic cleanup on context cancellation
- Perfect for request-scoped operations

**When to Use:**
- Web request handlers
- gRPC service methods
- Background services with cancellation
- Integration with existing context-aware code

### 🟠 **TIER 3: ADVANCED (Use With Extreme Care)**

#### 5. `GetSecretWithTimeout(secretID, timeout) (*SecretWithContext, error)`
**Security Level**: ⭐⭐⭐ (Medium - Requires Discipline)

```go
// ⚠️ REQUIRES CAREFUL HANDLING
secret, err := vault.GetSecretWithTimeout("crypto/key", 5*time.Minute)
if err != nil {
    return err
}
defer secret.Close() // CRITICAL: Always defer Close()

for _, file := range manyFiles {
    select {
    case <-secret.Done():
        return fmt.Errorf("secret expired during processing")
    default:
        if err := encryptFile(secret.Data(), file); err != nil {
            return err
        }
    }
}
```

**Why Use This:**
- Direct access to secret data
- Suitable for multi-step operations
- Automatic timeout-based cleanup
- Context monitoring capabilities

**When to Use:**
- Multi-step operations requiring same secret
- Connection pools with authentication
- Batch processing within time limits
- When callback pattern is insufficient

**CRITICAL Requirements:**
- ✅ **ALWAYS** use `defer secret.Close()`
- ✅ **ALWAYS** monitor `secret.Done()` channel
- ✅ **NEVER** store `secret.Data()` in variables
- ✅ **NEVER** pass secret data to other goroutines

#### 6. `GetSecretWithContext(ctx, secretID) (*SecretWithContext, error)`
**Security Level**: ⭐⭐⭐ (Medium - Requires Discipline)

```go
// ⚠️ REQUIRES CAREFUL HANDLING
secret, err := vault.GetSecretWithContext(ctx, "service/key")
if err != nil {
    return err
}
defer secret.Close() // CRITICAL: Always defer Close()

for {
    select {
    case <-ctx.Done():
        return ctx.Err()
    case <-secret.Done():
        return fmt.Errorf("secret context expired")
    case work := <-workQueue:
        if err := processWork(secret.Data(), work); err != nil {
            return err
        }
    }
}
```

**When to Use:**
- Background services with graceful shutdown
- Stream processing with cancellation
- Long-running context-aware operations

**Same critical requirements as above apply.**

## Security Best Practices

### 🔒 **Primary Security Rules**

#### 1. Secret Lifetime Management
```go
// ✅ CORRECT: Minimal lifetime
vault.UseSecret("key", func(data []byte) error {
    return immediateUse(data)
})

// ❌ WRONG: Extended lifetime
secret, _ := vault.GetSecretWithTimeout("key", 1*time.Hour)
globalVar = secret.Data() // NEVER DO THIS
```

#### 2. Memory Reference Safety
```go
// ✅ CORRECT: Use within callback only
vault.UseSecret("token", func(token []byte) error {
    auth := "Bearer " + string(token)
    req.Header.Set("Authorization", auth)
    return client.Do(req)
})

// ❌ WRONG: Storing references
var globalToken []byte
vault.UseSecret("token", func(token []byte) error {
    globalToken = token // DANGEROUS: Reference becomes invalid
    return nil
})
```

#### 3. Proper Cleanup Patterns
```go
// ✅ CORRECT: Immediate defer
secret, err := vault.GetSecretWithTimeout("key", 5*time.Minute)
if err != nil {
    return err
}
defer secret.Close() // ALWAYS defer immediately

// ❌ WRONG: Delayed or conditional cleanup
secret, _ := vault.GetSecretWithTimeout("key", 5*time.Minute)
if someCondition {
    secret.Close() // Might not be called!
}
```

#### 4. Context and Timeout Monitoring
```go
// ✅ CORRECT: Monitor all relevant channels
secret, err := vault.GetSecretWithContext(ctx, "key")
if err != nil {
    return err
}
defer secret.Close()

for {
    select {
    case <-ctx.Done():        // Parent cancellation
        return ctx.Err()
    case <-secret.Done():     // Secret expiration
        return fmt.Errorf("secret expired")
    case work := <-workChan:  // Actual work
        processWork(secret.Data(), work)
    }
}
```

### 🛡️ **Advanced Security Practices**

#### 1. Secret Validation
```go
// ✅ GOOD: Validate secrets before use
err := vault.UseSecret("api/key", func(key []byte) error {
    if len(key) == 0 {
        return fmt.Errorf("empty API key")
    }
    if len(key) < 32 {
        return fmt.Errorf("API key too short")
    }
    return useAPIKey(key)
})
```

#### 2. Error Handling Without Leakage
```go
// ✅ GOOD: Generic error messages
err := vault.UseSecret("db/password", func(pwd []byte) error {
    db, err := sql.Open("postgres", buildDSN(pwd))
    if err != nil {
        // Don't include password in error
        return fmt.Errorf("database connection failed")
    }
    return db.Ping()
})

// ❌ WRONG: Password in error message
err := vault.UseSecret("db/password", func(pwd []byte) error {
    dsn := buildDSN(pwd)
    db, err := sql.Open("postgres", dsn)
    if err != nil {
        return fmt.Errorf("failed to connect with DSN: %s", dsn) // LEAKED!
    }
    return db.Ping()
})
```

#### 3. Concurrent Access Patterns
```go
// ✅ GOOD: Each goroutine gets its own secret
for _, task := range tasks {
    go func(t Task) {
        vault.UseSecret("worker/key", func(key []byte) error {
            return processTask(t, key)
        })
    }(task)
}

// ❌ WRONG: Sharing secret across goroutines
secret, _ := vault.GetSecretWithTimeout("worker/key", 10*time.Minute)
defer secret.Close()
for _, task := range tasks {
    go func(t Task) {
        processTask(t, secret.Data()) // DANGEROUS: Shared access
    }(task)
}
```

## Common Usage Patterns

### 🔄 **Pattern 1: Database Access**
```go
func connectToDatabase(vault *Vault) (*sql.DB, error) {
    var db *sql.DB
    err := vault.UseSecret("db/credentials", func(cred []byte) error {
        // Parse credentials (assuming JSON)
        var dbCred DatabaseCredentials
        if err := json.Unmarshal(cred, &dbCred); err != nil {
            return err
        }
        
        dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s",
            dbCred.Host, dbCred.User, dbCred.Password, dbCred.Database)
        
        var err error
        db, err = sql.Open("postgres", dsn)
        if err != nil {
            return err
        }
        
        // Test connection while we have credentials
        return db.Ping()
    })
    
    if err != nil {
        if db != nil {
            db.Close()
        }
        return nil, err
    }
    
    return db, nil
}
```

### 🔄 **Pattern 2: HTTP Client with Authentication**
```go
func makeAuthenticatedRequest(vault *Vault, url string) (*http.Response, error) {
    return vault.UseSecret("api/token", func(token []byte) error {
        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
            return err
        }
        
        req.Header.Set("Authorization", "Bearer "+string(token))
        req.Header.Set("User-Agent", "MyApp/1.0")
        
        client := &http.Client{Timeout: 30 * time.Second}
        resp, err := client.Do(req)
        if err != nil {
            return err
        }
        
        if resp.StatusCode >= 400 {
            resp.Body.Close()
            return fmt.Errorf("API request failed: %d", resp.StatusCode)
        }
        
        // Caller takes ownership of response
        return nil
    })
}
```

### 🔄 **Pattern 3: File Encryption**
```go
func encryptFiles(vault *Vault, inputFiles []string, outputDir string) error {
    return vault.UseSecret("encryption/key", func(key []byte) error {
        if len(key) != 32 {
            return fmt.Errorf("invalid key length: expected 32, got %d", len(key))
        }
        
        cipher, err := aes.NewCipher(key)
        if err != nil {
            return fmt.Errorf("failed to create cipher: %w", err)
        }
        
        for _, inputFile := range inputFiles {
            outputFile := filepath.Join(outputDir, filepath.Base(inputFile)+".enc")
            if err := encryptFile(cipher, inputFile, outputFile); err != nil {
                return fmt.Errorf("failed to encrypt %s: %w", inputFile, err)
            }
        }
        
        return nil
    })
}
```

### 🔄 **Pattern 4: Long-Running Service**
```go
func runBackgroundService(ctx context.Context, vault *Vault) error {
    // Use context-based secret for service lifetime
    secret, err := vault.GetSecretWithContext(ctx, "service/credentials")
    if err != nil {
        return fmt.Errorf("failed to get service credentials: %w", err)
    }
    defer secret.Close()
    
    // Initialize service with credentials
    service, err := initializeService(secret.Data())
    if err != nil {
        return fmt.Errorf("failed to initialize service: %w", err)
    }
    defer service.Close()
    
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-secret.Done():
            return fmt.Errorf("service credentials expired")
        case <-ticker.C:
            if err := service.PerformPeriodicTask(); err != nil {
                log.Printf("Periodic task failed: %v", err)
                // Continue running unless it's a fatal error
                if isFatalError(err) {
                    return err
                }
            }
        }
    }
}
```

### 🔄 **Pattern 5: Batch Processing with Timeout**
```go
func processBatchWithSecret(vault *Vault, batch []WorkItem) error {
    // Use timeout to ensure secret doesn't live too long
    secret, err := vault.GetSecretWithTimeout("batch/key", 10*time.Minute)
    if err != nil {
        return err
    }
    defer secret.Close()
    
    processed := 0
    for i, item := range batch {
        // Check if secret expired or was cancelled
        select {
        case <-secret.Done():
            return fmt.Errorf("secret expired after processing %d/%d items", processed, len(batch))
        default:
        }
        
        if err := processWorkItem(secret.Data(), item); err != nil {
            return fmt.Errorf("failed to process item %d: %w", i, err)
        }
        
        processed++
        
        // Optional: log progress
        if processed%100 == 0 {
            log.Printf("Processed %d/%d items", processed, len(batch))
        }
    }
    
    return nil
}
```

## Anti-Patterns & Security Pitfalls

### ❌ **Anti-Pattern 1: Secret Hoarding**
```go
// ❌ WRONG: Long-lived secret storage
type ServiceConfig struct {
    APIKey    []byte // NEVER store secrets in structs
    DBPassword string // NEVER store passwords as fields
}

// ✅ CORRECT: Secret access on demand
type ServiceConfig struct {
    vault    *Vault
    apiKeyID string
    dbCredID string
}

func (c *ServiceConfig) makeAPICall() error {
    return c.vault.UseSecret(c.apiKeyID, func(key []byte) error {
        return performAPICall(key)
    })
}
```

### ❌ **Anti-Pattern 2: Secret Sharing Across Goroutines**
```go
// ❌ WRONG: Sharing secret data across goroutines
secret, _ := vault.GetSecretWithTimeout("key", 5*time.Minute)
defer secret.Close()

var wg sync.WaitGroup
for _, task := range tasks {
    wg.Add(1)
    go func(t Task) {
        defer wg.Done()
        processTask(secret.Data(), t) // DANGEROUS: Concurrent access
    }(task)
}
wg.Wait()

// ✅ CORRECT: Each goroutine gets its own secret
var wg sync.WaitGroup
for _, task := range tasks {
    wg.Add(1)
    go func(t Task) {
        defer wg.Done()
        vault.UseSecret("key", func(key []byte) error {
            return processTask(key, t)
        })
    }(task)
}
wg.Wait()
```

### ❌ **Anti-Pattern 3: Ignoring Context Cancellation**
```go
// ❌ WRONG: Not monitoring context or secret expiration
secret, _ := vault.GetSecretWithContext(ctx, "key")
defer secret.Close()

for work := range workChannel {
    // WRONG: No context checking
    processWork(secret.Data(), work)
}

// ✅ CORRECT: Proper context and secret monitoring
secret, err := vault.GetSecretWithContext(ctx, "key")
if err != nil {
    return err
}
defer secret.Close()

for {
    select {
    case <-ctx.Done():
        return ctx.Err()
    case <-secret.Done():
        return fmt.Errorf("secret expired")
    case work, ok := <-workChannel:
        if !ok {
            return nil // Channel closed
        }
        if err := processWork(secret.Data(), work); err != nil {
            return err
        }
    }
}
```

### ❌ **Anti-Pattern 4: Secret Leakage in Logs**
```go
// ❌ WRONG: Logging secrets or secret-containing data
vault.UseSecret("api/key", func(key []byte) error {
    log.Printf("Using API key: %s", string(key)) // LEAKED!
    
    req := buildRequest(key)
    log.Printf("Request: %+v", req) // Might contain key!
    
    return client.Do(req)
})

// ✅ CORRECT: Safe logging without secrets
vault.UseSecret("api/key", func(key []byte) error {
    log.Printf("Making authenticated API request")
    
    req := buildRequest(key)
    // Log only non-sensitive parts
    log.Printf("Request URL: %s, Method: %s", req.URL.Path, req.Method)
    
    return client.Do(req)
})
```

### ❌ **Anti-Pattern 5: Ignoring Cleanup Errors**
```go
// ❌ WRONG: Not handling cleanup properly
secret, err := vault.GetSecretWithTimeout("key", 5*time.Minute)
if err != nil {
    return err
}
// Missing defer secret.Close() entirely!

result := processWithSecret(secret.Data())
secret.Close() // Might not be reached if processWithSecret panics

// ✅ CORRECT: Guaranteed cleanup
secret, err := vault.GetSecretWithTimeout("key", 5*time.Minute)
if err != nil {
    return err
}
defer secret.Close() // Always called, even on panic

return processWithSecret(secret.Data())
```

## Performance Considerations

### ⚡ **Performance Best Practices**

#### 1. Minimize Secret Retrieval Frequency
```go
// ❌ INEFFICIENT: Retrieving secret for each operation
for _, item := range manyItems {
    vault.UseSecret("key", func(key []byte) error {
        return processItem(key, item) // Secret retrieved each time
    })
}

// ✅ EFFICIENT: Single secret retrieval for batch
vault.UseSecret("key", func(key []byte) error {
    for _, item := range manyItems {
        if err := processItem(key, item); err != nil {
            return err
        }
    }
    return nil
})
```

#### 2. Appropriate Timeout Selection
```go
// ❌ INEFFICIENT: Too short timeout causes frequent re-retrieval
secret, err := vault.GetSecretWithTimeout("key", 1*time.Second) // Too short!

// ❌ INSECURE: Too long timeout increases exposure
secret, err := vault.GetSecretWithTimeout("key", 24*time.Hour) // Too long!

// ✅ BALANCED: Reasonable timeout based on operation duration
secret, err := vault.GetSecretWithTimeout("key", 5*time.Minute) // Just right
```

#### 3. Efficient Error Handling
```go
// ❌ INEFFICIENT: Creating many error objects
vault.UseSecret("key", func(key []byte) error {
    for i, item := range items {
        if err := process(key, item); err != nil {
            return fmt.Errorf("item %d failed: %w", i, err) // New error each time
        }
    }
    return nil
})

// ✅ EFFICIENT: Batch error reporting
vault.UseSecret("key", func(key []byte) error {
    var errors []error
    for i, item := range items {
        if err := process(key, item); err != nil {
            errors = append(errors, fmt.Errorf("item %d: %w", i, err))
        }
    }
    if len(errors) > 0 {
        return fmt.Errorf("batch processing failed: %v", errors)
    }
    return nil
})
```

### 📊 **Performance Monitoring**

#### Key Metrics to Track:
- **Secret Retrieval Frequency**: Too high indicates inefficient usage
- **Secret Lifetime**: How long secrets stay in memory
- **Timeout Events**: Frequency of timeout-based cleanup
- **Context Cancellation**: Frequency of early termination
- **Memory Usage**: Peak secret-related memory consumption

#### Monitoring Implementation:
```go
// Performance monitoring wrapper
func (v *Vault) UseSecretWithMetrics(secretID string, fn func(data []byte) error) error {
    start := time.Now()
    defer func() {
        metrics.RecordSecretUsage(secretID, time.Since(start))
    }()
    
    return v.UseSecret(secretID, fn)
}
```

## Error Handling

### 🚨 **Error Handling Strategies**

#### 1. Graceful Degradation
```go
func authenticateUser(vault *Vault, userID string) error {
    // Try primary authentication method
    err := vault.UseSecret("auth/primary-key", func(key []byte) error {
        return primaryAuth(userID, key)
    })
    
    if err != nil {
        log.Printf("Primary auth failed for user %s: %v", userID, err)
        
        // Fallback to secondary method
        return vault.UseSecret("auth/secondary-key", func(key []byte) error {
            return secondaryAuth(userID, key)
        })
    }
    
    return nil
}
```

#### 2. Retry with Backoff
```go
func robustSecretOperation(vault *Vault, secretID string) error {
    backoff := time.Second
    maxRetries := 3
    
    for attempt := 0; attempt < maxRetries; attempt++ {
        err := vault.UseSecret(secretID, func(data []byte) error {
            return performOperation(data)
        })
        
        if err == nil {
            return nil // Success
        }
        
        // Check if error is retryable
        if !isRetryableError(err) {
            return err
        }
        
        if attempt < maxRetries-1 {
            log.Printf("Operation failed (attempt %d/%d): %v. Retrying in %v",
                attempt+1, maxRetries, err, backoff)
            time.Sleep(backoff)
            backoff *= 2 // Exponential backoff
        }
    }
    
    return fmt.Errorf("operation failed after %d attempts", maxRetries)
}
```

#### 3. Context-Aware Error Handling
```go
func contextAwareOperation(ctx context.Context, vault *Vault) error {
    return vault.UseSecretWithContext(ctx, "operation/key", func(key []byte) error {
        // Long-running operation with context checking
        for i := 0; i < 1000; i++ {
            select {
            case <-ctx.Done():
                return fmt.Errorf("operation cancelled at step %d: %w", i, ctx.Err())
            default:
            }
            
            if err := processStep(key, i); err != nil {
                return fmt.Errorf("step %d failed: %w", i, err)
            }
        }
        return nil
    })
}
```

### 🔍 **Error Classification**

#### Retryable Errors:
- Network timeouts
- Temporary service unavailability
- Rate limiting
- Transient vault errors

#### Non-Retryable Errors:
- Invalid credentials
- Permission denied
- Secret not found
- Malformed secret data

```go
func isRetryableError(err error) bool {
    if err == nil {
        return false
    }
    
    // Check for specific error types
    var netErr net.Error
    if errors.As(err, &netErr) && netErr.Timeout() {
        return true
    }
    
    // Check for HTTP status codes
    if httpErr, ok := err.(*HTTPError); ok {
        return httpErr.StatusCode >= 500 || httpErr.StatusCode == 429
    }
    
    // Check for vault-specific errors
    if vaultErr, ok := err.(*VaultError); ok {
        return vaultErr.IsRetryable()
    }
    
    return false
}
```

## Testing Guidelines

### 🧪 **Testing Secret-Using Code**

#### 1. Mock Vault for Unit Tests
```go
// Test interface
type VaultInterface interface {
    UseSecret(secretID string, fn func(data []byte) error) error
    UseSecretString(secretID string, fn func(secret string) error) error
    // ... other methods
}

// Mock implementation
type MockVault struct {
    secrets map[string][]byte
    errors  map[string]error
}

func (m *MockVault) UseSecret(secretID string, fn func(data []byte) error) error {
    if err, exists := m.errors[secretID]; exists {
        return err
    }
    
    data, exists := m.secrets[secretID]
    if !exists {
        return fmt.Errorf("secret not found: %s", secretID)
    }
    
    return fn(data)
}

// Test usage
func TestUserAuthentication(t *testing.T) {
    mockVault := &MockVault{
        secrets: map[string][]byte{
            "auth/key": []byte("test-secret-key"),
        },
    }
    
    err := authenticateUser(mockVault, "testuser")
    assert.NoError(t, err)
}
```

#### 2. Integration Tests with Real Vault
```go
func TestIntegrationWithRealVault(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    vault := setupTestVault(t)
    defer vault.Close()
    
    // Store test secret
    testSecret := []byte("integration-test-secret")
    _, err := vault.StoreSecret("test/integration", testSecret, nil)
    require.NoError(t, err)
    
    // Test retrieval and usage
    err = vault.UseSecret("test/integration", func(data []byte) error {
        assert.Equal(t, testSecret, data)
        return nil
    })
    assert.NoError(t, err)
}
```

#### 3. Timeout and Context Testing
```go
func TestSecretTimeout(t *testing.T) {
    vault := setupTestVault(t)
    defer vault.Close()
    
    // Test timeout behavior
    err := vault.UseSecretWithTimeout("test/secret", 100*time.Millisecond, func(data []byte) error {
        time.Sleep(200 * time.Millisecond) // Longer than timeout
        return nil
    })
    
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "deadline exceeded")
}

func TestSecretContextCancellation(t *testing.T) {
    vault := setupTestVault(t)
    defer vault.Close()
    
    ctx, cancel := context.WithCancel(context.Background())
    
    // Cancel context in background
    go func() {
        time.Sleep(50 * time.Millisecond)
        cancel()
    }()
    
    err := vault.UseSecretWithContext(ctx, "test/secret", func(data []byte) error {
        time.Sleep(100 * time.Millisecond) // Longer than cancellation
        return nil
    })
    
    assert.Error(t, err)
    assert.ErrorIs(t, err, context.Canceled)
}
```

### 🎯 **Test Coverage Guidelines**

#### Core Test Scenarios:
1. **Happy Path**: Normal secret usage
2. **Error Cases**: Secret not found, permission denied
3. **Timeout Cases**: Operation timeout, context cancellation
4. **Cleanup Verification**: Memory clearing, resource cleanup
5. **Concurrent Access**: Multiple goroutines accessing secrets
6. **Edge Cases**: Empty secrets, large secrets, malformed data

#### Security Test Scenarios:
1. **Memory Leakage**: Verify secrets are cleared from memory
2. **Reference Safety**: Ensure secret references become invalid
3. **Panic Handling**: Verify cleanup occurs even on panic
4. **Context Expiration**: Test behavior when contexts expire

## Monitoring & Logging

### 📊 **Monitoring Best Practices**

#### 1. Key Metrics to Track
```go
type VaultMetrics struct {
    SecretRetrievals      prometheus.Counter
    SecretUsageDuration   prometheus.Histogram
    SecretTimeouts        prometheus.Counter
    SecretErrors          prometheus.Counter
    ActiveSecrets         prometheus.Gauge
}

// Metrics wrapper
func (v *Vault) UseSecretWithMetrics(secretID string, fn func(data []byte) error) error {
    start := time.Now()
    v.metrics.SecretRetrievals.Inc()
    v.metrics.ActiveSecrets.Inc()
    
    defer func() {
        v.metrics.ActiveSecrets.Dec()
        v.metrics.SecretUsageDuration.Observe(time.Since(start).Seconds())
    }()
    
    err := v.UseSecret(secretID, fn)
    if err != nil {
        v.metrics.SecretErrors.Inc()
        if isTimeoutError(err) {
            v.metrics.SecretTimeouts.Inc()
        }
    }
    
    return err
}
```

#### 