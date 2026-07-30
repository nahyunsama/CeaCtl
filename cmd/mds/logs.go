package mds

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	appconfig "github.com/nahyunsama/ceactl/internal/config"
	"github.com/nahyunsama/ceactl/internal/llm/ollama"
	"github.com/nahyunsama/ceactl/internal/mds/commands"
	"github.com/nahyunsama/ceactl/internal/mds/config"
	"github.com/nahyunsama/ceactl/internal/mds/llmanalysis"
	"github.com/nahyunsama/ceactl/internal/mds/logcompressor"
	"github.com/spf13/cobra"
)

func LogsCommand(opts *commandOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "MDS log related commands",
	}

	cmd.AddCommand(LogsAnalyzeCommand(opts))

	return cmd
}

func LogsAnalyzeCommand(opts *commandOptions) *cobra.Command {
	var fromStr, toStr, file string

	c := &cobra.Command{
		Use:   "analyze",
		Short: "Group and summarize MDS log lines",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgFile, err := appconfig.LoadFile(opts.configPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %v", err)
			}
			if !cfgFile.LLMAnalysis.Enabled {
				return fmt.Errorf("log analysis is disabled; set `llm_analysis.enabled: true` in %s to use `mds logs analyze`", opts.configPath)
			}

			from, err := parseDayStart(fromStr)
			if err != nil {
				return fmt.Errorf("invalid --from: %v", err)
			}
			to, err := parseDayEnd(toStr)
			if err != nil {
				return fmt.Errorf("invalid --to: %v", err)
			}

			var reader io.Reader
			device := opts.deviceName

			if file != "" {
				f, err := os.Open(file)
				if err != nil {
					return fmt.Errorf("failed to open log file: %v", err)
				}
				defer f.Close()
				reader = f
			} else {
				cfg, err := config.LoadConfig(opts.configPath, opts.deviceName, opts.verbose)
				if err != nil {
					return fmt.Errorf("failed to load config: %v", err)
				}
				if device == "" {
					device = cfg.SwitchIP
				}

				body, err := commands.GetLoggingLogfile(cmd.Context(), cfg)
				if err != nil {
					return fmt.Errorf("failed to get logging logfile: %v", err)
				}
				reader = strings.NewReader(body)
			}

			result, err := logcompressor.Analyze(reader, from, to)
			if err != nil {
				return fmt.Errorf("failed to analyze log: %v", err)
			}

			backend := cfgFile.LLMAnalysis.Backend
			if shouldWriteFullLogReport(opts.verbose, backend) {
				if err := result.WriteReport(os.Stdout, 10); err != nil {
					return err
				}
			}

			if backend != "ollama" {
				return nil
			}

			userPrompt, err := llmanalysis.BuildUserPrompt(llmanalysis.PromptInput{
				Device:      device,
				FilterStart: from,
				FilterEnd:   to,
				Result:      result,
			})
			if err != nil {
				return fmt.Errorf("failed to build LLM analysis prompt: %v", err)
			}

			fmt.Fprintf(os.Stderr, "Requesting LLM analysis from %s (model: %s)...\n", cfgFile.LLMAnalysis.Ollama.Endpoint, cfgFile.LLMAnalysis.Ollama.Model)
			done := make(chan struct{})
			stopped := make(chan struct{})
			go func() {
				reportElapsed(os.Stderr, done)
				close(stopped)
			}()

			client := ollama.NewClient(
				cfgFile.LLMAnalysis.Ollama.Endpoint,
				cfgFile.LLMAnalysis.Ollama.Model,
			)
			chatResult, err := client.ChatDetailed(cmd.Context(), llmanalysis.SystemPrompt, userPrompt)
			close(done)
			<-stopped
			fmt.Fprintln(os.Stderr)
			if opts.verbose {
				if verboseErr := chatResult.WriteVerbose(os.Stderr); verboseErr != nil {
					return fmt.Errorf("failed to write verbose Ollama response: %v", verboseErr)
				}
			}
			if err != nil {
				return fmt.Errorf("failed to get LLM analysis: %v", err)
			}
			reply := chatResult.AssistantContent()

			if _, err := fmt.Fprintf(
				os.Stdout,
				"\n=== LLM Analysis (%s) ===\n\n%s\n",
				cfgFile.LLMAnalysis.Ollama.Model,
				reply,
			); err != nil {
				return err
			}

			eventIDs := llmanalysis.ReferencedEventIDs(
				reply,
				result.EventCount(),
			)

			if err := writeReferencedEventOutput(
				os.Stdout,
				result,
				eventIDs,
				opts.verbose,
			); err != nil {
				return err
			}

			_, err = fmt.Fprintln(
				os.Stderr,
				"\n※ 주의: LLM 분석에는 실수나 부정확한 내용이 포함될 수 있습니다. "+
					"최종 판단 전에 원본 로그와 위 인용 이벤트 원문을 반드시 확인하세요.",
			)
			return err
		},
	}

	c.Flags().StringVar(&fromStr, "from", "", "start date filter, YYYYMMDD (inclusive)")
	c.Flags().StringVar(&toStr, "to", "", "end date filter, YYYYMMDD (inclusive)")
	c.Flags().StringVar(&file, "file", "", "path to a local log file (skips device fetch)")

	return c
}

func shouldWriteFullLogReport(verbose bool, backend string) bool {
	return verbose || backend != "ollama"
}

func writeReferencedEventOutput(
	w io.Writer,
	result *logcompressor.Result,
	eventIDs []int,
	verbose bool,
) error {
	if verbose {
		return result.WriteEvidenceDetails(w, eventIDs)
	}
	return result.WriteCitedEventSummary(w, eventIDs)
}

func reportElapsed(w io.Writer, done <-chan struct{}) {
	start := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			fmt.Fprintf(w, "\r  waiting... %-8s", time.Since(start).Round(time.Second))
		}
	}
}

func parseDayStart(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse("20060102", s)
}

func parseDayEnd(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	day, err := time.Parse("20060102", s)
	if err != nil {
		return time.Time{}, err
	}
	return day.AddDate(0, 0, 1).Add(-time.Second), nil
}
