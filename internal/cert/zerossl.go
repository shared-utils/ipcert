package cert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ============================================================================
// Types
// ============================================================================

// ValidationDetails contains HTTP validation info for a certificate
type ValidationDetails struct {
	FileValidationURLHTTP string   `json:"file_validation_url_http"`
	FileValidationContent []string `json:"file_validation_content"`
}

// certificateInfo represents a ZeroSSL certificate
type certificateInfo struct {
	ID         string `json:"id"`
	CommonName string `json:"common_name"`
	Status     string `json:"status"`
	Validation struct {
		OtherMethods map[string]ValidationDetails `json:"other_methods"`
	} `json:"validation"`
}

// certificateDownloadResponse contains the downloaded certificate files
type certificateDownloadResponse struct {
	CertificateCrt string `json:"certificate.crt"`
	CaBundleCrt    string `json:"ca_bundle.crt"`
}

// APIError represents a ZeroSSL API error
type APIError struct {
	Code int    `json:"code"`
	Type string `json:"type"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("ZeroSSL API error: %s (code %d)", e.Type, e.Code)
}

// apiErrorResponse represents a ZeroSSL API error response
type apiErrorResponse struct {
	Success bool     `json:"success"`
	Error   APIError `json:"error"`
}

// ============================================================================
// Error Classification
// ============================================================================

// isFatalError checks if the error is a fatal error that should not be retried
func isFatalError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "api error 401") ||
		strings.Contains(errStr, "api error 403") ||
		strings.Contains(errStr, "invalid api key") ||
		strings.Contains(errStr, "invalid access key") ||
		strings.Contains(errStr, "access_key") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "unauthorized")
}

// isNotFoundError checks if the error indicates the certificate does not exist
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		// ZeroSSL error code 2803 = certificate_not_found
		return apiErr.Code == 2803 || apiErr.Type == "certificate_not_found"
	}
	return false
}

// isRetryableError checks if the error is a temporary/retryable error
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	if isFatalError(err) {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "API error 5") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "temporary failure")
}

// ============================================================================
// ZeroSSL Client
// ============================================================================

type zerosslClient struct {
	apiKey  string
	baseURL string
}

// ============================================================================
// Certificate Operations
// ============================================================================

// getCertificate returns full certificate info by ID
func (c *zerosslClient) getCertificate(ctx context.Context, certID string) (*certificateInfo, error) {
	body, err := c.get(ctx, "/certificates/"+certID)
	if err != nil {
		return nil, err
	}

	// Check for API error response (success: false)
	var errResp apiErrorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && !errResp.Success && errResp.Error.Type != "" {
		return nil, fmt.Errorf("API error: %s (code %d)", errResp.Error.Type, errResp.Error.Code)
	}

	var result certificateInfo
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// getCertificateStatus returns only the status of a certificate
func (c *zerosslClient) getCertificateStatus(ctx context.Context, certID string) (string, error) {
	body, err := c.get(ctx, "/certificates/"+certID)
	if err != nil {
		return "", err
	}

	var result struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	return result.Status, nil
}

// createCertificate creates a new certificate with the given IPs and CSR
func (c *zerosslClient) createCertificate(ctx context.Context, ips []string, csr string, validityDays int) (*certificateInfo, error) {
	form := url.Values{
		"certificate_domains":       {strings.Join(ips, ",")},
		"certificate_csr":           {csr},
		"certificate_validity_days": {fmt.Sprintf("%d", validityDays)},
	}

	body, err := c.post(ctx, "/certificates", form)
	if err != nil {
		return nil, err
	}

	var result certificateInfo
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if result.ID == "" {
		return nil, fmt.Errorf("invalid response: %s", body)
	}
	result.Status = "draft"
	return &result, nil
}

// verifyChallenge triggers HTTP validation for a certificate
func (c *zerosslClient) verifyChallenge(ctx context.Context, certID string) error {
	form := url.Values{"validation_method": {"HTTP_CSR_HASH"}}
	_, err := c.post(ctx, "/certificates/"+certID+"/challenges", form)
	return err
}

// downloadCertificate downloads the issued certificate files
func (c *zerosslClient) downloadCertificate(ctx context.Context, certID string) (*certificateDownloadResponse, error) {
	body, err := c.get(ctx, "/certificates/"+certID+"/download/return")
	if err != nil {
		return nil, err
	}

	var result certificateDownloadResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ============================================================================
// HTTP Methods
// ============================================================================

func (c *zerosslClient) get(ctx context.Context, path string) ([]byte, error) {
	reqURL := c.buildURL(path)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, body)
	}
	return body, nil
}

func (c *zerosslClient) post(ctx context.Context, path string, form url.Values) ([]byte, error) {
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
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, body)
	}
	return body, nil
}

func (c *zerosslClient) buildURL(path string) string {
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return fmt.Sprintf("%s%s%saccess_key=%s", c.baseURL, path, separator, c.apiKey)
}
