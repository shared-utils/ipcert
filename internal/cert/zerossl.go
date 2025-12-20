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

type ValidationDetails struct {
	FileValidationURLHTTP string   `json:"file_validation_url_http"`
	FileValidationContent []string `json:"file_validation_content"`
}

type createCertificateResponse struct {
	ID         string `json:"id"`
	Validation struct {
		OtherMethods map[string]ValidationDetails `json:"other_methods"`
	} `json:"validation"`
}

type certificateDownloadResponse struct {
	CertificateCrt string `json:"certificate.crt"`
	CaBundleCrt    string `json:"ca_bundle.crt"`
}

type zerosslClient struct {
	apiKey  string
	baseURL string
}

func (c *zerosslClient) createCertificate(ctx context.Context, ips []string, csr string, validityDays int) (*createCertificateResponse, error) {
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

	var result createCertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if result.ID == "" {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("invalid response: %s", body)
	}
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

func (c *zerosslClient) post(ctx context.Context, path string, form url.Values) (*http.Response, error) {
	reqURL := fmt.Sprintf("%s%s?access_key=%s", c.baseURL, path, c.apiKey)
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
	reqURL := fmt.Sprintf("%s%s?access_key=%s", c.baseURL, path, c.apiKey)
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
