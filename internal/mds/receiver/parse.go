package receiver

import (
	"encoding/json"
	"fmt"
)

func ParseVersionResponse(data []byte) (VersionBody, error) {
	var resp VersionResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return VersionBody{}, err
	}
	return resp.InsAPI.Outputs.Output.Body, nil
}

func ParseInventoryResponse(data []byte) (InventoryBody, error) {
	var resp InventoryResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return InventoryBody{}, err
	}
	return resp.InsAPI.Outputs.Output.Body, nil
}

func ParseCLIASCIIResponse(data []byte) (string, error) {
	var resp CLIASCIIResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", err
	}

	output := resp.InsAPI.Outputs.Output
	if output.Code != "200" {
		return "", fmt.Errorf(
			"NX-API command failed: code=%s msg=%s clierror=%s",
			output.Code,
			output.Message,
			output.ClientError,
		)
	}

	return output.Body, nil
}
