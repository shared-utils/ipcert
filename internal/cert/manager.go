package cert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ============================================================================
// Types
// ============================================================================

// Config holds the certificate manager configuration
type Config struct {
	CertDir          string
	CertValidityDays int
	ZeroSSLApiKey    string
	ZeroSSLBaseURL   string
	PublicIps        []string
}

// Manager manages SSL certificates
type Manager interface {
	Load() (*x509.Certificate, error)
	Obtain(ctx context.Context) error
}

type manager struct {
	cfg Config
}

// taskData represents the data saved in a task file for recovery
type taskData struct {
	CertID     string                       `json:"cert_id"`
	IPs        []string                     `json:"ips"`
	Status     string                       `json:"status"`
	Validation map[string]ValidationDetails `json:"validation"`
	CreatedAt  time.Time                    `json:"created_at"`
}

// ============================================================================
// Constructor
// ============================================================================

// NewManager creates a new certificate manager
func NewManager(cfg Config) (Manager, error) {
	if err := os.MkdirAll(cfg.CertDir, 0755); err != nil {
		return nil, fmt.Errorf("create cert dir: %w", err)
	}
	return &manager{cfg: cfg}, nil
}

// ============================================================================
// Public Methods
// ============================================================================

// Load loads and validates an existing certificate from disk
func (m *manager) Load() (*x509.Certificate, error) {
	certPath := filepath.Join(m.cfg.CertDir, "cert.pem")
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Validate expiry
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate expired or not yet valid")
	}

	// Validate IPs
	certIPs := make(map[string]bool)
	for _, ip := range cert.IPAddresses {
		certIPs[ip.String()] = true
	}
	for _, ip := range m.cfg.PublicIps {
		if !certIPs[ip] {
			return nil, fmt.Errorf("certificate missing IP: %s", ip)
		}
	}

	return cert, nil
}

// Obtain obtains a new certificate, resuming from local task if exists
func (m *manager) Obtain(ctx context.Context) error {
	client := &zerosslClient{apiKey: m.cfg.ZeroSSLApiKey, baseURL: m.cfg.ZeroSSLBaseURL}

	// Step 1: Try to resume from local task file
	certInfo, err := m.tryResumeTask(ctx, client)
	if err != nil {
		return err
	}

	// Step 2: Handle existing task or create new certificate
	if certInfo != nil {
		return m.handleExistingCert(ctx, client, certInfo)
	}

	// Step 3: Create new certificate
	return m.createNewCert(ctx, client)
}

// ============================================================================
// Obtain Sub-steps
// ============================================================================

// tryResumeTask attempts to load and validate a local task file
func (m *manager) tryResumeTask(ctx context.Context, client *zerosslClient) (*certificateInfo, error) {
	fmt.Println("[1/4] Checking for existing task file...")

	certInfo, err := m.loadTask()
	if err != nil {
		fmt.Printf("  └─ Warning: failed to load task file: %v\n", err)
		return nil, nil
	}
	if certInfo == nil {
		fmt.Println("  └─ No existing task found")
		return nil, nil
	}

	fmt.Printf("  └─ Found existing task (ID: %s, cached status: %s)\n", certInfo.ID, certInfo.Status)

	// Verify with ZeroSSL that the certificate still exists
	fmt.Println("  └─ Verifying with ZeroSSL...")
	latestInfo, err := client.getCertificate(ctx, certInfo.ID)
	if err != nil {
		if isFatalError(err) {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
		if isNotFoundError(err) {
			fmt.Printf("  └─ Certificate not found on ZeroSSL: %v\n", err)
			fmt.Println("  └─ Cleaning up stale task...")
			m.deleteTask()
			return nil, nil
		}
		// Network/server error - fail and let user retry
		return nil, fmt.Errorf("failed to verify certificate: %w", err)
	}

	// Check if certificate is still usable
	switch latestInfo.Status {
	case "cancelled", "revoked", "expired":
		fmt.Printf("  └─ Certificate is %s, cleaning up...\n", latestInfo.Status)
		m.deleteTask()
		return nil, nil
	}

	fmt.Printf("  └─ Remote status: %s\n", latestInfo.Status)
	return latestInfo, nil
}

// handleExistingCert handles an existing certificate based on its status
func (m *manager) handleExistingCert(ctx context.Context, client *zerosslClient, certInfo *certificateInfo) error {
	switch certInfo.Status {
	case "issued":
		fmt.Println("[2/4] Certificate already issued")
		fmt.Println("[3/4] Skipping validation...")
		return m.downloadCert(ctx, client, certInfo.ID)

	case "pending_validation":
		fmt.Println("[2/4] Resuming pending validation...")
		return m.waitAndDownload(ctx, client, certInfo)

	case "draft":
		fmt.Println("[2/4] Resuming draft certificate...")
		return m.validateAndDownload(ctx, client, certInfo)

	default:
		fmt.Printf("  └─ Unknown status '%s', cleaning up...\n", certInfo.Status)
		m.deleteTask()
		return m.createNewCert(ctx, client)
	}
}

// createNewCert creates a new certificate from scratch
func (m *manager) createNewCert(ctx context.Context, client *zerosslClient) error {
	fmt.Println("[2/4] Creating new certificate...")

	// Generate CSR
	csr, err := m.generateCSR()
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}
	fmt.Println("  └─ CSR generated")
	fmt.Printf("  └─ Private key saved to: %s/privkey.pem\n", m.cfg.CertDir)

	// Create certificate with retry
	var certInfo *certificateInfo
	for attempt := 1; ; attempt++ {
		certInfo, err = client.createCertificate(ctx, m.cfg.PublicIps, csr, m.cfg.CertValidityDays)
		if err == nil {
			break
		}
		if isFatalError(err) {
			return fmt.Errorf("authentication failed: %w", err)
		}
		if !isRetryableError(err) {
			return fmt.Errorf("create certificate: %w", err)
		}
		fmt.Printf("  └─ Attempt %d failed: %v, retrying in 5s...\n", attempt, err)
		if err := m.sleep(ctx, 5*time.Second); err != nil {
			return err
		}
	}
	fmt.Printf("  └─ Certificate created (ID: %s)\n", certInfo.ID)

	// Save task for recovery
	if err := m.saveTask(certInfo); err != nil {
		fmt.Printf("  └─ Warning: %v\n", err)
	}

	return m.validateAndDownload(ctx, client, certInfo)
}

// ============================================================================
// Validation & Download
// ============================================================================

// validateAndDownload validates a draft certificate and waits for issuance
func (m *manager) validateAndDownload(ctx context.Context, client *zerosslClient, certInfo *certificateInfo) error {
	// Verify validation info exists
	for _, ip := range m.cfg.PublicIps {
		if _, ok := certInfo.Validation.OtherMethods[ip]; !ok {
			return fmt.Errorf("validation info not found for IP: %s", ip)
		}
	}

	// Start validation server
	server, err := m.startValidationServer(certInfo.Validation.OtherMethods)
	if err != nil {
		return err
	}
	defer server.Shutdown(context.Background())
	time.Sleep(2 * time.Second)

	// Trigger validation with retry
	fmt.Println("[3/4] Triggering validation...")
	for attempt := 1; ; attempt++ {
		err := client.verifyChallenge(ctx, certInfo.ID)
		if err == nil {
			fmt.Println("  └─ Validation triggered")
			break
		}
		if isFatalError(err) {
			return fmt.Errorf("authentication failed: %w", err)
		}
		if !isRetryableError(err) {
			return fmt.Errorf("trigger validation: %w", err)
		}
		fmt.Printf("  └─ Attempt %d failed: %v, retrying in 5s...\n", attempt, err)
		if err := m.sleep(ctx, 5*time.Second); err != nil {
			return err
		}
	}

	return m.pollAndDownload(ctx, client, certInfo.ID)
}

// waitAndDownload waits for a pending_validation certificate to be issued
func (m *manager) waitAndDownload(ctx context.Context, client *zerosslClient, certInfo *certificateInfo) error {
	// Start validation server in case ZeroSSL retries
	fmt.Println("[3/4] Starting validation server...")
	server, err := m.startValidationServer(certInfo.Validation.OtherMethods)
	if err != nil {
		return err
	}
	defer server.Shutdown(context.Background())

	return m.pollAndDownload(ctx, client, certInfo.ID)
}

// pollAndDownload polls for certificate issuance and downloads it
func (m *manager) pollAndDownload(ctx context.Context, client *zerosslClient, certID string) error {
	fmt.Println("[4/4] Waiting for issuance...")

	pollCount := 0
	lastStatus := ""

	for {
		if err := m.sleep(ctx, 5*time.Second); err != nil {
			return err
		}

		pollCount++
		status, err := client.getCertificateStatus(ctx, certID)
		if err != nil {
			if isFatalError(err) {
				return fmt.Errorf("authentication failed: %w", err)
			}
			if isRetryableError(err) {
				fmt.Printf("  └─ [%d] Error: %v (retrying...)\n", pollCount, err)
				continue
			}
			return fmt.Errorf("get status: %w", err)
		}

		if status != lastStatus {
			fmt.Printf("  └─ [%d] Status: %s\n", pollCount, status)
			lastStatus = status
		} else {
			fmt.Printf("  └─ [%d] Still %s...\n", pollCount, status)
		}

		if status == "issued" {
			fmt.Println("  └─ Certificate issued!")
			return m.downloadCert(ctx, client, certID)
		}
	}
}

// downloadCert downloads and saves the certificate
func (m *manager) downloadCert(ctx context.Context, client *zerosslClient, certID string) error {
	fmt.Println("[4/4] Downloading certificate...")

	var certFiles *certificateDownloadResponse
	var err error

	for attempt := 1; ; attempt++ {
		certFiles, err = client.downloadCertificate(ctx, certID)
		if err == nil {
			break
		}
		if isFatalError(err) {
			return fmt.Errorf("authentication failed: %w", err)
		}
		if !isRetryableError(err) {
			return fmt.Errorf("download certificate: %w", err)
		}
		fmt.Printf("  └─ Attempt %d failed: %v, retrying in 5s...\n", attempt, err)
		if err := m.sleep(ctx, 5*time.Second); err != nil {
			return err
		}
	}

	// Save certificate files
	certPath := filepath.Join(m.cfg.CertDir, "cert.pem")
	chainPath := filepath.Join(m.cfg.CertDir, "chain.pem")
	fullchainPath := filepath.Join(m.cfg.CertDir, "fullchain.pem")

	if err := os.WriteFile(certPath, []byte(certFiles.CertificateCrt), 0644); err != nil {
		return fmt.Errorf("write cert.pem: %w", err)
	}
	fmt.Printf("  └─ Saved: %s\n", certPath)

	if err := os.WriteFile(chainPath, []byte(certFiles.CaBundleCrt), 0644); err != nil {
		return fmt.Errorf("write chain.pem: %w", err)
	}
	fmt.Printf("  └─ Saved: %s\n", chainPath)

	fullchain := certFiles.CertificateCrt + "\n" + certFiles.CaBundleCrt
	if err := os.WriteFile(fullchainPath, []byte(fullchain), 0644); err != nil {
		return fmt.Errorf("write fullchain.pem: %w", err)
	}
	fmt.Printf("  └─ Saved: %s\n", fullchainPath)

	// Clean up task file
	m.deleteTask()

	fmt.Println("✓ Certificate obtained successfully!")
	return nil
}

// ============================================================================
// Task File Management
// ============================================================================

// taskFileName generates a unique task file name from sorted IPs
func (m *manager) taskFileName() string {
	ips := make([]string, len(m.cfg.PublicIps))
	copy(ips, m.cfg.PublicIps)
	sort.Strings(ips)
	joined := strings.Join(ips, ",")
	encoded := base64.RawURLEncoding.EncodeToString([]byte(joined))
	return filepath.Join(m.cfg.CertDir, encoded+".task")
}

// saveTask saves the current task to a local file
func (m *manager) saveTask(certInfo *certificateInfo) error {
	data := taskData{
		CertID:     certInfo.ID,
		IPs:        m.cfg.PublicIps,
		Status:     certInfo.Status,
		Validation: certInfo.Validation.OtherMethods,
		CreatedAt:  time.Now(),
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal task: %w", err)
	}

	taskFile := m.taskFileName()
	if err := os.WriteFile(taskFile, jsonData, 0644); err != nil {
		return fmt.Errorf("write task: %w", err)
	}

	fmt.Printf("  └─ Task saved: %s\n", taskFile)
	return nil
}

// loadTask loads a task from a local file
func (m *manager) loadTask() (*certificateInfo, error) {
	taskFile := m.taskFileName()
	data, err := os.ReadFile(taskFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read task: %w", err)
	}

	var task taskData
	if err := json.Unmarshal(data, &task); err != nil {
		return nil, fmt.Errorf("unmarshal task: %w", err)
	}

	certInfo := &certificateInfo{
		ID:         task.CertID,
		CommonName: task.IPs[0],
		Status:     task.Status,
	}
	certInfo.Validation.OtherMethods = task.Validation

	fmt.Printf("  └─ Loaded task: %s (created: %s)\n", taskFile, task.CreatedAt.Format(time.RFC3339))
	return certInfo, nil
}

// deleteTask removes the task file
func (m *manager) deleteTask() {
	taskFile := m.taskFileName()
	if err := os.Remove(taskFile); err != nil && !os.IsNotExist(err) {
		fmt.Printf("  └─ Warning: failed to delete task: %v\n", err)
		return
	}
	fmt.Printf("  └─ Task deleted: %s\n", taskFile)
}

// ============================================================================
// Helpers
// ============================================================================

// generateCSR generates a new private key and CSR
func (m *manager) generateCSR() (string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	// Save private key
	keyPath := filepath.Join(m.cfg.CertDir, "privkey.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return "", err
	}

	// Create CSR
	template := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: m.cfg.PublicIps[0]},
	}
	for _, ipStr := range m.cfg.PublicIps {
		if ip := net.ParseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})), nil
}

// startValidationServer starts an HTTP server for ACME validation
func (m *manager) startValidationServer(methods map[string]ValidationDetails) (*http.Server, error) {
	pathToContent := make(map[string]string)
	for _, details := range methods {
		if details.FileValidationURLHTTP == "" {
			continue
		}
		parts := strings.Split(details.FileValidationURLHTTP, "/")
		if len(parts) >= 4 {
			path := "/" + strings.Join(parts[3:], "/")
			pathToContent[path] = strings.Join(details.FileValidationContent, "\n")
			fmt.Printf("  └─ Validation endpoint: %s\n", path)
		}
	}

	server := &http.Server{
		Addr: ":80",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("  └─ Validation request: %s\n", r.URL.Path)
			if content, ok := pathToContent[r.URL.Path]; ok {
				w.Write([]byte(content))
			} else {
				for _, c := range pathToContent {
					w.Write([]byte(c))
					return
				}
			}
		}),
	}

	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		return nil, fmt.Errorf("bind port 80 (try sudo): %w", err)
	}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			fmt.Printf("  └─ Server error: %v\n", err)
		}
	}()

	fmt.Println("  └─ Validation server started on :80")
	return server, nil
}

// sleep waits for the given duration or until context is cancelled
func (m *manager) sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
