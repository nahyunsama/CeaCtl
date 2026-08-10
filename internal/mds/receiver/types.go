package receiver

type VersionResponse struct {
	InsAPI struct {
		Outputs struct {
			Output struct {
				Body VersionBody `json:"body"`
			} `json:"output"`
		} `json:"outputs"`
	} `json:"ins_api"`
}

type VersionBody struct {
	HostName   string `json:"host_name"`
	Version    string `json:"sys_ver_str"`
	UptimeDays int    `json:"kern_uptm_days"`
	UptimeHrs  int    `json:"kern_uptm_hrs"`
	UptimeMins int    `json:"kern_uptm_mins"`
	UptimeSecs int    `json:"kern_uptm_secs"`
}

type InventoryResponse struct {
	InsAPI struct {
		Outputs struct {
			Output struct {
				Body InventoryBody `json:"body"`
			} `json:"output"`
		} `json:"outputs"`
	} `json:"ins_api"`
}

type InventoryItem struct {
	Name      string `json:"name"`
	ProductID string `json:"productid"`
	SerialNum string `json:"serialnum"`
}

type InventoryBody struct {
	TableInv struct {
		RowInv []InventoryItem `json:"ROW_inv"`
	} `json:"TABLE_inv"`
}

type CLIASCIIResponse struct {
	InsAPI struct {
		Outputs struct {
			Output struct {
				Body        string `json:"body"`
				Code        string `json:"code"`
				Message     string `json:"msg"`
				Input       string `json:"input"`
				ClientError string `json:"clierror"`
			} `json:"output"`
		} `json:"outputs"`
	} `json:"ins_api"`
}
