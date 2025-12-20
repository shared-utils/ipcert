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
	// Generate CSR and private key
	csr, err := m.generateCSR()
	if err != nil {
		return err
	}

	// Create certificate via ZeroSSL API
	client := &zerosslClient{apiKey: m.cfg.ZeroSSLApiKey, baseURL: m.cfg.ZeroSSLBaseURL}
	createResp, err := client.createCertificate(ctx, m.cfg.PublicIps, csr, m.cfg.CertValidityDays)
	if err != nil {
		return err
	}

	// Verify all IPs have validation info
	for _, ip := range m.cfg.PublicIps {
		if _, ok := createResp.Validation.OtherMethods[ip]; !ok {
			return fmt.Errorf("validation info not found for IP: %s", ip)
		}
	}

	// Start validation server
	server, err := m.startValidationServer(createResp.Validation.OtherMethods)
	if err != nil {
		return err
	}
	defer server.Shutdown(context.Background())
	time.Sleep(2 * time.Second)

	// Trigger validation
	fmt.Println("Triggering domain validation...")
	if err := client.verifyChallenge(ctx, createResp.ID); err != nil {
		return err
	}

	// Poll for certificate
	fmt.Println("Waiting for certificate to be issued...")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}

		status, err := client.getCertificateStatus(ctx, createResp.ID)
		if err != nil {
			return err
		}

		fmt.Printf("Certificate status: %s\n", status)
		if status == "issued" {
			return m.downloadAndSave(ctx, client, createResp.ID)
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

func (m *manager) downloadAndSave(ctx context.Context, client *zerosslClient, certID string) error {
	certFiles, err := client.downloadCertificate(ctx, certID)
	if err != nil {
		return err
	}

	certPath := filepath.Join(m.cfg.CertDir, "cert.pem")
	chainPath := filepath.Join(m.cfg.CertDir, "chain.pem")
	fullchainPath := filepath.Join(m.cfg.CertDir, "fullchain.pem")

	if err := os.WriteFile(certPath, []byte(certFiles.CertificateCrt), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(chainPath, []byte(certFiles.CaBundleCrt), 0644); err != nil {
		return err
	}
	fullchain := certFiles.CertificateCrt + "\n" + certFiles.CaBundleCrt
	return os.WriteFile(fullchainPath, []byte(fullchain), 0644)
}
