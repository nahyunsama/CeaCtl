package main

import (
	"os"

	"github.com/nahyunsama/ceactl/cmd"
)

func main() {
	// Required by legacy Cisco firmware; weakens TLS policy process-wide.
	os.Setenv("GODEBUG", "tlssha1=1")
	cmd.Execute()
}
