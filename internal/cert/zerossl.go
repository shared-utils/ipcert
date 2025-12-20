package cert

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// isFatalError checks if the error is a fatal error that should not be retried
func isFatalError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "api error 401") || // Unauthorized
		strings.Contains(errStr, "api error 403") || // Forbidden
		strings.Contains(errStr, "invalid api key") ||
		strings.Contains(errStr, "invalid access key") ||
		strings.Contains(errStr, "access_key") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "unauthorized")
}

// isRetryableError checks if the error is a temporary/retryable error
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	// Never retry fatal errors
	if isFatalError(err) {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "API error 5") || // 5xx errors
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "temporary failure")
}

type ValidationDetails struct {
	FileValidationURLHTTP string   `json:"file_validation_url_http"`
	FileValidationContent []string `json:"file_validation_content"`
}

type certificateInfo struct {
	ID         string `json:"id"`
	CommonName string `json:"common_name"`
	Status     string `json:"status"`
	Validation struct {
		OtherMethods map[string]ValidationDetails `json:"other_methods"`
	} `json:"validation"`
}

type listCertificatesResponse struct {
	Results []certificateInfo `json:"results"`
}

type certificateDownloadResponse struct {
	CertificateCrt string `json:"certificate.crt"`
	CaBundleCrt    string `json:"ca_bundle.crt"`
}

type zerosslClient struct {
	apiKey  string
	baseURL string
}

// listCertificates returns all certificates matching the given status
func (c *zerosslClient) listCertificates(ctx context.Context, status string) ([]certificateInfo, error) {
	path := "/certificates?certificate_status=" + status
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result listCertificatesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Results, nil
}

// getCertificate returns full certificate info including validation details
func (c *zerosslClient) getCertificate(ctx context.Context, certID string) (*certificateInfo, error) {
	resp, err := c.get(ctx, "/certificates/"+certID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result certificateInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// findExistingCertificate finds an existing certificate for the given IPs
func (c *zerosslClient) findExistingCertificate(ctx context.Context, ips []string) (*certificateInfo, error) {
	targetIPs := make(map[string]bool)
	for _, ip := range ips {
		targetIPs[ip] = true
	}

	// Check these statuses in order of preference
	statuses := []string{"issued", "pending_validation", "draft"}

	for _, status := range statuses {
		fmt.Printf("  └─ Checking status '%s'...\n", status)
		certs, err := c.listCertificates(ctx, status)
		if err != nil {
			fmt.Printf("     Error listing %s certificates: %v\n", status, err)
			continue
		}
		fmt.Printf("     Found %d certificates with status '%s'\n", len(certs), status)

		for _, cert := range certs {
			fmt.Printf("     - Cert ID: %s, CommonName: %s\n", cert.ID, cert.CommonName)

			// For IP certificates, CommonName is the IP address
			// Check if CommonName matches any of our target IPs
			if targetIPs[cert.CommonName] {
				fmt.Printf("     ✓ Found matching certificate!\n")
				// Get full details including validation info
				return c.getCertificate(ctx, cert.ID)
			}
		}
	}

	return nil, nil // No existing certificate found
}

func (c *zerosslClient) createCertificate(ctx context.Context, ips []string, csr string, validityDays int) (*certificateInfo, error) {
	form := url.Values{
		"certificate_domains":       {strings.Join(ips, ",")},
		"certificate_csr":           {csr},
		"certificate_validity_days": {fmt.Sprintf("%d", validityDays)},
	}

	resp, err := c.post(ctx, "/certificates", form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result certificateInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if result.ID == "" {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("invalid response: %s", body)
	}
	result.Status = "draft"
	return &result, nil
}

func (c *zerosslClient) verifyChallenge(ctx context.Context, certID string) error {
	form := url.Values{"validation_method": {"HTTP_CSR_HASH"}}
	resp, err := c.post(ctx, "/certificates/"+certID+"/challenges", form)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (c *zerosslClient) getCertificateStatus(ctx context.Context, certID string) (string, error) {
	resp, err := c.get(ctx, "/certificates/"+certID)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Status, nil
}

func (c *zerosslClient) downloadCertificate(ctx context.Context, certID string) (*certificateDownloadResponse, error) {
	resp, err := c.get(ctx, "/certificates/"+certID+"/download/return")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result certificateDownloadResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *zerosslClient) buildURL(path string) string {
	// Handle paths that already have query parameters
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return fmt.Sprintf("%s%s%saccess_key=%s", c.baseURL, path, separator, c.apiKey)
}

func (c *zerosslClient) post(ctx context.Context, path string, form url.Values) (*http.Response, error) {
	reqURL := c.buildURL(path)
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, body)
	}
	return resp, nil
}

func (c *zerosslClient) get(ctx context.Context, path string) (*http.Response, error) {
	reqURL := c.buildURL(path)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, body)
	}
	return resp, nil
}
