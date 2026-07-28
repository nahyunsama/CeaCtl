package transceiver

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
)

func (c *Client) PostXML(ctx context.Context, payload any) ([]byte, error) {
	body, err := xml.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	// UCS Manager's XML API requires this media type even though the body is XML.
	req.Header.Set("content-type", "application/x-www-form-urlencoded")

	if c.Verbose {
		fmt.Fprintf(os.Stderr, "[verbose] sending request: %s %s\n", req.Method, c.BaseURL)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, response: %s", resp.StatusCode, string(data))
	}

	return data, nil
}
