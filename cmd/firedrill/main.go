// Command firedrill checks whether a company's safeguards actually hold.
package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sk1122/firedrill/connector"
	_ "github.com/sk1122/firedrill/connectors/aws"
	_ "github.com/sk1122/firedrill/connectors/configsrc"
	_ "github.com/sk1122/firedrill/connectors/ctlog"
	_ "github.com/sk1122/firedrill/connectors/dns"
	_ "github.com/sk1122/firedrill/connectors/files"
	_ "github.com/sk1122/firedrill/connectors/gcp"
	_ "github.com/sk1122/firedrill/connectors/github"
	_ "github.com/sk1122/firedrill/connectors/google"
	_ "github.com/sk1122/firedrill/connectors/hrcsv"
	_ "github.com/sk1122/firedrill/connectors/semgrep"
	_ "github.com/sk1122/firedrill/connectors/web"
	"github.com/sk1122/firedrill/internal/run"
)

// version is set by release builds with -ldflags. Otherwise resolveVersion
// reads the module version Go records in the binary, which go install sets.
var version = ""

// resolveVersion returns the release version, the module version from go
// install, or "dev" for a local build.
func resolveVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return strings.TrimPrefix(bi.Main.Version, "v")
	}
	return "dev"
}

// exitError carries a chosen exit code without printing a usage message.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

var projectDir string

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "firedrill",
		Short:         "Your rules, drilled weekly, with proof.",
		Version:       resolveVersion(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&projectDir, "dir", ".firedrill", "the Firedrill folder")
	root.AddCommand(initCmd(), connectCmd(), runCmd(), verifyCmd(), verifyDomainCmd(), exportCmd(), listCmd(), explainCmd(), reportCmd(), validateCmd(), testCmd(), hubCmd())
	return root
}

func main() {
	v := resolveVersion()
	run.Version = v
	connector.Version = v
	if err := rootCmd().Execute(); err != nil {
		if ex, ok := errors.AsType[exitError](err); ok {
			os.Exit(ex.code)
		}
		fmt.Fprintln(os.Stderr, "firedrill:", err)
		os.Exit(2)
	}
}
