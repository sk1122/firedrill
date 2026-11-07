// Command firedrill checks whether a company's safeguards actually hold.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sk1122/firedrill/connector"
	_ "github.com/sk1122/firedrill/connectors/aws"
	_ "github.com/sk1122/firedrill/connectors/configsrc"
	_ "github.com/sk1122/firedrill/connectors/ctlog"
	_ "github.com/sk1122/firedrill/connectors/dns"
	_ "github.com/sk1122/firedrill/connectors/files"
	_ "github.com/sk1122/firedrill/connectors/github"
	_ "github.com/sk1122/firedrill/connectors/google"
	_ "github.com/sk1122/firedrill/connectors/hrcsv"
	_ "github.com/sk1122/firedrill/connectors/semgrep"
	_ "github.com/sk1122/firedrill/connectors/web"
	"github.com/sk1122/firedrill/internal/run"
)

// version is set at build time with -ldflags.
var version = "0.0.1"

// exitError carries a chosen exit code without printing a usage message.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

var projectDir string

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "firedrill",
		Short:         "Your rules, drilled weekly, with proof.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&projectDir, "dir", ".firedrill", "the Firedrill folder")
	root.AddCommand(initCmd(), connectCmd(), runCmd(), verifyCmd(), verifyDomainCmd(), exportCmd(), listCmd(), explainCmd(), reportCmd(), validateCmd())
	return root
}

func main() {
	run.Version = version
	connector.Version = version
	if err := rootCmd().Execute(); err != nil {
		if ex, ok := errors.AsType[exitError](err); ok {
			os.Exit(ex.code)
		}
		fmt.Fprintln(os.Stderr, "firedrill:", err)
		os.Exit(2)
	}
}
