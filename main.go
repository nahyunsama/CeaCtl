package main

import (
	"os"

	"github.com/nahyunsama/ceactl/cmd"
)

func main() {
	// Some supported Cisco firmware still uses SHA-1 TLS signatures; this
	// process-wide compatibility switch weakens the default TLS policy.
	os.Setenv("GODEBUG", "tlssha1=1")
	cmd.Execute()
}
