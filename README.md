# CeaCtl

Cisco Enterprise API Control (`ceactl`) is a Go CLI for querying Cisco MDS
and UCS Manager devices. It currently supports MDS inventory and firmware
queries, UCSM server inventory, and an experimental MDS log-analysis workflow
with local Ollama models.

## Features

- Cisco MDS NX-API integration over HTTPS
- Cisco UCS Manager XML API integration over HTTPS
- MDS firmware version and hardware inventory queries
- UCSM server inventory queries
- MDS log collection or local log-file input
- Mechanical log grouping by severity, facility, mnemonic, interface, and VSAN
- Optional LLM-assisted log analysis through the Ollama Chat API
- Configurable device profiles and verbose request logging

## Requirements

- Go 1.26.3 or a compatible version matching [`go.mod`](go.mod)
- Network access and valid credentials for the target MDS or UCSM device
- NX-API enabled on MDS devices
- [Ollama](https://docs.ollama.com/quickstart) and a downloaded model for LLM
  log analysis (optional)

## Build

```bash
go mod download
go build -o ceactl .
```

On Windows, use `go build -o ceactl.exe .` and replace `./ceactl` with
`./ceactl.exe` in the examples below.

## Configuration

Copy the example configuration before running the CLI:

```bash
cp .config.yaml.example .config.yaml
```

```yaml
devices:
  mds-lab:
    type: mds
    host: 192.0.2.10
    port: "8443"
    username: admin
    password: change-me
    insecure_tls: true

  ucsm-lab:
    type: ucsm
    host: 192.0.2.20
    port: "443"
    username: admin
    password: change-me
    insecure_tls: true

llm_analysis:
  enabled: false
  backend: ollama
  ollama:
    endpoint: http://localhost:11434
    model: gemma4:e2b
  output:
    translate: true
    target_lang: ko_KR
```

Each device must define `type`, `host`, `port`, `username`, and `password`.
When exactly one device of the requested type exists, CeaCtl selects it
automatically. When multiple devices of that type exist, choose one with
`--device`.

`insecure_tls: true` disables TLS certificate verification and is intended
for lab devices or self-signed certificates. Use certificate verification in
production environments. The configuration contains plaintext credentials;
`.config.yaml` is ignored by Git, but it should still be protected with
appropriate file permissions.

The `llm_analysis.output` fields are reserved for future output controls. The
current implementation loads them but does not yet use them to translate or
change the response language.

## Commands

| Command | Description |
| --- | --- |
| `ceactl mds version` | Show the MDS hostname, firmware version, and uptime. |
| `ceactl mds inventory` | Show MDS component names, product IDs, and serial numbers. |
| `ceactl mds logs analyze` | Fetch, group, and optionally analyze MDS logs. |
| `ceactl ucsm servers` | Show UCSM server DN, model, serial number, and operational state. |

The `mds` and `ucsm` command groups share these flags:

| Flag | Description |
| --- | --- |
| `--config <path>` | Configuration file path (default: `.config.yaml`). |
| `--device`, `-d <name>` | Device profile name from the configuration. |
| `--verbose`, `-v` | Print request/session details; log analysis also prints the complete compressed input, cited source evidence, and Ollama API response. |

Examples:

```bash
./ceactl mds version --device mds-lab
./ceactl mds inventory -d mds-lab
./ceactl ucsm servers --device ucsm-lab
./ceactl mds version --config ./configs/lab.yaml --verbose
```

## MDS Log Analysis with Ollama

`mds logs analyze` parses and semantically compresses the log locally before
sending pipe-delimited events to Ollama. The default output contains the
model's analysis followed by one-line summaries for individually cited Event
IDs such as `E1` and `E2`. Use `--verbose` to also display the complete
compressed input and the exact source messages behind cited events.

### 1. Install and start Ollama

Install Ollama by following the official instructions for
[Windows, macOS, or Linux](https://docs.ollama.com/quickstart). Make sure the
server is running; depending on the installation, starting the Ollama app may
do this automatically. It can also be started from a terminal:

```bash
ollama serve
```

### 2. Download the configured model

The model name must be identical in Ollama and `.config.yaml`:

```bash
ollama pull gemma4:e2b
ollama ls
```

You can use another chat-capable Ollama model by changing both the pull command
and `llm_analysis.ollama.model`.

### 3. Enable the backend

```yaml
llm_analysis:
  enabled: true
  backend: ollama
  ollama:
    endpoint: http://localhost:11434
    model: gemma4:e2b
```

Set `endpoint` to the Ollama server's base URL without `/api`; CeaCtl appends
`/api/chat` internally. The current Ollama client does not support API-key or
other authentication headers.

### 4. Analyze device or local logs

Fetch `show logging logfile` from an MDS device:

```bash
./ceactl mds logs analyze --device mds-lab
```

Analyze an existing local file without contacting the MDS device:

```bash
./ceactl mds logs analyze --file ./samples/mds.log
```

Filter either source by an inclusive date range in `YYYYMMDD` format:

```bash
./ceactl mds logs analyze \
  --device mds-lab \
  --from 20260701 \
  --to 20260715

./ceactl mds logs analyze \
  --file ./samples/mds.log \
  --from 20260701 \
  --to 20260715
```

`--from` and `--to` are optional. A local-file run still requires a valid
configuration file with at least one device because the command loads the
global configuration before reading the file.

The Ollama request is non-streaming, uses a 128K requested context window and
temperature `0`, and can wait for up to 10 minutes. Large logs or a model's
first load may therefore take some time; the CLI prints an elapsed-time counter
while it waits.

Use `--verbose` to print the complete compressed log report and cited source
evidence, plus the complete `/api/chat` JSON response to stderr. The response
includes Ollama's performance fields such as `total_duration`,
`load_duration`, `prompt_eval_count`, `prompt_eval_duration`, `eval_count`, and
`eval_duration`:

```bash
./ceactl mds logs analyze --file ./samples/mds.log --verbose
```

LLM output is preliminary troubleshooting material and may be incomplete or
incorrect. Use `--verbose` to confirm cited events against the source log
details, and collect additional diagnostics before making operational or
hardware decisions.
If `endpoint` points to another host, the grouped log content is sent to that
host.

## Project Structure

```text
.
|-- main.go                         # CLI entry point
|-- cmd/
|   |-- root.go                     # Root command
|   |-- mds/                        # MDS commands and flags
|   `-- ucsm/                       # UCSM commands and flags
|-- internal/
|   |-- config/                     # YAML loading and device selection
|   |-- mds/
|   |   |-- commands/               # MDS query operations
|   |   |-- llmanalysis/            # Ollama client and analysis prompts
|   |   |-- logcompressor/          # Log parsing, grouping, and evidence
|   |   |-- receiver/               # NX-API JSON response parsing
|   |   `-- transceiver/            # NX-API HTTPS client
|   `-- ucsm/
|       |-- commands/               # UCSM query operations
|       |-- receiver/               # UCSM XML response parsing
|       `-- transceiver/            # UCSM XML session and HTTPS client
`-- .config.yaml.example            # Configuration template
```

## Test

```bash
go test ./...
```

## Roadmap

- Additional MDS and UCSM commands
- JSON and other output formats
- File output support
- Confirmed MDS configuration changes, such as zones and zonesets
- NX-API and UCSM API-level error parsing
- Relative log windows such as `--around` and `--window`
- Configurable LLM output language and translation

## License

This project is licensed under the [MIT License](LICENSE).
