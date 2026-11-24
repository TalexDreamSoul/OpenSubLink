package substore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrFileShareNotFound = errors.New("file share not found")
	ErrFileGateway       = errors.New("Sub-Store file sharing requires a protected backend URL")
)

type File struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type FileShare struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"exp"`
	Mode      string `json:"mode"`
	Count     int64  `json:"count"`
	UsedCount int64  `json:"usedCount"`
}

func ValidFileName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00\r\n")
}

func (c *Client) ListFiles(ctx context.Context) ([]File, error) {
	var files []File
	err := c.fileJSON(ctx, http.MethodGet, "/api/files", nil, &files)
	return files, err
}

func (c *Client) CreateTextFile(ctx context.Context, name, text string) (File, error) {
	var file File
	payload := map[string]string{"name": "osl-" + rand.Text(), "displayName": name, "type": "file", "source": "local", "content": text}
	err := c.fileJSON(ctx, http.MethodPost, "/api/files", payload, &file)
	return file, err
}

func (c *Client) DeleteFile(ctx context.Context, name string) error {
	return c.fileJSON(ctx, http.MethodDelete, "/api/file/"+url.PathEscape(name), nil, nil)
}

func (c *Client) ListFileShares(ctx context.Context, name string) ([]FileShare, error) {
	var shares []FileShare
	query := url.Values{"type": {"file"}, "name": {name}}
	err := c.fileJSON(ctx, http.MethodGet, "/api/tokens?"+query.Encode(), nil, &shares)
	return shares, err
}

func (c *Client) CreateFileShare(ctx context.Context, name string) (string, error) {
	var share FileShare
	payload := map[string]any{
		"payload": map[string]string{"type": "file", "name": name, "token": rand.Text()},
		"options": map[string]string{"mode": "duration", "expiresIn": "7d"},
	}
	err := c.fileJSON(ctx, http.MethodPost, "/api/token", payload, &share)
	if err == nil && share.Token == "" {
		return "", errors.New("Sub-Store returned an empty share token")
	}
	return share.Token, err
}

func (c *Client) RevokeFileShare(ctx context.Context, name, token string) error {
	query := url.Values{"type": {"file"}, "name": {name}}
	return c.fileJSON(ctx, http.MethodDelete, "/api/token/"+url.PathEscape(token)+"?"+query.Encode(), nil, nil)
}

func (c *Client) DownloadFile(ctx context.Context, name, token string) ([]byte, error) {
	if !ValidFileName(name) || token == "" || len(token) > 256 {
		return nil, ErrFileShareNotFound
	}
	origin, err := c.fileOrigin()
	if err != nil {
		return nil, err
	}
	shares, err := c.ListFileShares(ctx, name)
	if err != nil {
		return nil, err
	}
	for _, share := range shares {
		if share.Type != "file" || share.Name != name || subtle.ConstantTimeCompare([]byte(share.Token), []byte(token)) != 1 {
			continue
		}
		if (share.ExpiresAt != 0 && share.ExpiresAt <= time.Now().UnixMilli()) ||
			(share.Mode == "count" && (share.Count <= 0 || share.UsedCount < 0 || share.UsedCount >= share.Count)) {
			return nil, ErrFileShareNotFound
		}
		query := url.Values{"token": {token}}
		// The public Sub-Store gateway consumes count-limited tokens atomically.
		return c.fileRequest(ctx, http.MethodGet, origin+"/share/file/"+url.PathEscape(name)+"?"+query.Encode(), nil)
	}
	return nil, ErrFileShareNotFound
}

func (c *Client) fileOrigin() (string, error) {
	base, err := url.Parse(c.baseURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") ||
		strings.Trim(base.Path, "/") == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return "", ErrFileGateway
	}
	return (&url.URL{Scheme: base.Scheme, Host: base.Host}).String(), nil
}

func (c *Client) fileJSON(ctx context.Context, method, path string, payload, result any) error {
	if _, err := c.fileOrigin(); err != nil {
		return err
	}
	body, err := c.fileRequest(ctx, method, c.baseURL+path, payload)
	if err != nil {
		return err
	}
	response := struct {
		Status string `json:"status"`
		Data   any    `json:"data"`
	}{Data: result}
	if err := json.Unmarshal(body, &response); err != nil || response.Status != "success" {
		return errors.New("invalid Sub-Store file API response")
	}
	return nil
}

func (c *Client) fileRequest(ctx context.Context, method, endpoint string, payload any) ([]byte, error) {
	var data []byte
	if payload != nil {
		var err error
		data, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("invalid Sub-Store file request")
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := *c.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("Sub-Store file request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrFileShareNotFound
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("Sub-Store file request returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes+1))
	if err != nil || int64(len(body)) > c.maxResponseBytes {
		return nil, errors.New("unable to read Sub-Store file response within the configured limit")
	}
	return body, nil
}
