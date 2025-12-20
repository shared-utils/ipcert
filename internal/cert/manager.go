package cert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	CertDir          string
	CertValidityDays int
	ZeroSSLApiKey    string
	ZeroSSLBaseURL   string
	PublicIps        []string
}

type Manager interface {
	Load() (*x509.Certificate, error)
	Obtain(ctx context.Context) error
}

type manager struct {
	cfg Config
}

func NewManager(cfg Config) (Manager, error) {
	if err := os.MkdirAll(cfg.CertDir, 0755); err != nil {
		return nil, fmt.Errorf("create cert dir: %w", err)
	}
	return &manager{cfg: cfg}, nil
}

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

func (m *manager) Obtain(ctx context.Context) error {
	client := &zerosslClient{apiKey: m.cfg.ZeroSSLApiKey, baseURL: m.cfg.ZeroSSLBaseURL}

	// Step 1: Check for existing certificate first (with retry)
	fmt.Println("[1/4] Checking for existing certificate...")
	var certInfo *certificateInfo
	for attempt := 1; ; attempt++ {
		var err error
		certInfo, err = client.findExistingCertificate(ctx, m.cfg.PublicIps)
		if err == nil {
			break
		}
		if isFatalError(err) {
			return fmt.Errorf("authentication failed (check your API key): %w", err)
		}
		if !isRetryableError(err) {
			fmt.Printf("  └─ Warning: %v (non-retryable, skipping)\n", err)
			break
		}
		fmt.Printf("  └─ Attempt %d failed: %v, retrying in 5s...\n", attempt, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}

	if certInfo != nil {
		fmt.Printf("  └─ Found existing certificate\n")
		fmt.Printf("     ID: %s\n", certInfo.ID)
		fmt.Printf("     Status: %s\n", certInfo.Status)

		switch certInfo.Status {
		case "issued":
			fmt.Println("[2/4] Certificate already issued, skipping validation")
			fmt.Println("[3/4] Skipping...")
			return m.downloadAndSaveWithRetry(ctx, client, certInfo.ID)

		case "pending_validation":
			fmt.Println("[2/4] Certificate pending validation, resuming...")
			return m.waitForIssuance(ctx, client, certInfo)

		case "draft":
			fmt.Println("[2/4] Certificate in draft, need to validate...")
			return m.validateAndWait(ctx, client, certInfo)
		}
	}

	fmt.Println("  └─ No existing certificate found")

	// Step 2: Create new certificate (with retry)
	fmt.Println("[2/4] Creating new certificate...")
	csr, err := m.generateCSR()
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}
	fmt.Println("  └─ CSR generated")
	fmt.Printf("  └─ Private key saved to: %s/privkey.pem\n", m.cfg.CertDir)

	for attempt := 1; ; attempt++ {
		certInfo, err = client.createCertificate(ctx, m.cfg.PublicIps, csr, m.cfg.CertValidityDays)
		if err == nil {
			break
		}
		if isFatalError(err) {
			return fmt.Errorf("authentication failed (check your API key): %w", err)
		}
		if !isRetryableError(err) {
			return fmt.Errorf("create certificate: %w", err)
		}
		fmt.Printf("  └─ Attempt %d failed: %v, retrying in 5s...\n", attempt, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	fmt.Printf("  └─ Certificate created (ID: %s)\n", certInfo.ID)

	return m.validateAndWait(ctx, client, certInfo)
}

func (m *manager) validateAndWait(ctx context.Context, client *zerosslClient, certInfo *certificateInfo) error {
	// Verify all IPs have validation info
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

	// Trigger validation (with retry)
	fmt.Println("[3/4] Triggering domain validation...")
	for attempt := 1; ; attempt++ {
		err := client.verifyChallenge(ctx, certInfo.ID)
		if err == nil {
			fmt.Println("  └─ Validation triggered successfully")
			break
		}
		if isFatalError(err) {
			return fmt.Errorf("authentication failed (check your API key): %w", err)
		}
		if !isRetryableError(err) {
			return fmt.Errorf("trigger validation: %w", err)
		}
		fmt.Printf("  └─ Attempt %d failed: %v, retrying in 5s...\n", attempt, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}

	return m.pollForIssuance(ctx, client, certInfo.ID)
}

func (m *manager) waitForIssuance(ctx context.Context, client *zerosslClient, certInfo *certificateInfo) error {
	// Start validation server in case ZeroSSL retries validation
	fmt.Println("[3/4] Starting validation server (ZeroSSL may retry validation)...")
	server, err := m.startValidationServer(certInfo.Validation.OtherMethods)
	if err != nil {
		return err
	}
	defer server.Shutdown(context.Background())

	return m.pollForIssuance(ctx, client, certInfo.ID)
}

func (m *manager) pollForIssuance(ctx context.Context, client *zerosslClient, certID string) error {
	fmt.Println("[4/4] Waiting for certificate to be issued...")
	pollCount := 0
	lastStatus := ""
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}

		pollCount++
		status, err := client.getCertificateStatus(ctx, certID)
		if err != nil {
			if isFatalError(err) {
				return fmt.Errorf("authentication failed (check your API key): %w", err)
			}
			if isRetryableError(err) {
				fmt.Printf("  └─ [%d] Error: %v (retrying...)\n", pollCount, err)
				continue
			}
			return fmt.Errorf("get certificate status: %w", err)
		}

		if status != lastStatus {
			fmt.Printf("  └─ [%d] Status: %s\n", pollCount, status)
			lastStatus = status
		} else {
			fmt.Printf("  └─ [%d] Still %s...\n", pollCount, status)
		}

		if status == "issued" {
			fmt.Println("  └─ Certificate issued!")
			return m.downloadAndSaveWithRetry(ctx, client, certID)
		}
	}
}

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
			fmt.Printf("Validation endpoint registered: %s\n", path)
		}
	}

	server := &http.Server{
		Addr: ":80",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("Validation request: %s\n", r.URL.Path)
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

	// Try to bind port 80 and check for errors
	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		return nil, fmt.Errorf("failed to bind port 80 (try running with sudo): %w", err)
	}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Validation server error: %v\n", err)
		}
	}()

	fmt.Println("Validation server started on :80")
	return server, nil
}

func (m *manager) downloadAndSaveWithRetry(ctx context.Context, client *zerosslClient, certID string) error {
	fmt.Println("[4/4] Downloading certificate...")

	var certFiles *certificateDownloadResponse
	for attempt := 1; ; attempt++ {
		var err error
		certFiles, err = client.downloadCertificate(ctx, certID)
		if err == nil {
			break
		}
		if isFatalError(err) {
			return fmt.Errorf("authentication failed (check your API key): %w", err)
		}
		if !isRetryableError(err) {
			return fmt.Errorf("download certificate: %w", err)
		}
		fmt.Printf("  └─ Attempt %d failed: %v, retrying in 5s...\n", attempt, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}

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

	fmt.Println("✓ Certificate obtained successfully!")
	return nil
}
