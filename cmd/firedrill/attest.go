package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sk1122/firedrill/internal/attest"
	"github.com/sk1122/firedrill/internal/run"
	"github.com/sk1122/firedrill/internal/tag"
)

func attestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Record the GitHub artifact attestation that covers a CI run's tags",
	}
	var records, checksums, id, url, bundle string
	record := &cobra.Command{
		Use:   "record",
		Short: "Write the sidecar naming the attestation over one checksums file",
		Long: "In CI, firedrill run writes <records>/attest/<time>.sha256 listing each tag it wrote.\n" +
			"The workflow attests that file with actions/attest-build-provenance (subject-checksums),\n" +
			"then this command writes <records>/attest/<time>.json naming the checksums file's hash\n" +
			"and the attestation's ID and URL, and keeps a copy of the bundle. It makes no network call.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if records == "" {
				records = defaultRecords()
			}
			path, err := attest.Record(records, checksums, id, url, bundle, time.Now(), os.Getenv)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Recorded", path)
			return nil
		},
	}
	record.Flags().StringVar(&records, "records", "", "where records live (default .firedrill/local)")
	record.Flags().StringVar(&checksums, "checksums", "", "the checksums file firedrill run wrote")
	record.Flags().StringVar(&id, "attestation-id", "", "the attestation ID the action output")
	record.Flags().StringVar(&url, "attestation-url", "", "the attestation URL the action output")
	record.Flags().StringVar(&bundle, "bundle", "", "the bundle file the action output (bundle-path)")
	_ = record.MarkFlagRequired("checksums")
	cmd.AddCommand(record)
	return cmd
}

// tagCheck is one tag's line in verify's output.
type tagCheck struct {
	Drill       string `json:"drill"`
	Target      string `json:"target,omitempty"`
	Time        string `json:"time"`
	Stream      string `json:"stream,omitempty"`
	Attestation string `json:"attestation"`
}

type recordsCheck struct {
	Histories   int                 `json:"histories"`
	Tags        int                 `json:"tags"`
	ChainBroken []string            `json:"chain_broken,omitempty"`
	Redacted    int                 `json:"redacted,omitempty"`
	Diffs       run.DiffChainStatus `json:"diffs"`
	Attestation attest.Status       `json:"attestation"`
	Attested    int                 `json:"tags_attested"`
	Unattested  int                 `json:"tags_unattested"`
	Mismatched  int                 `json:"tags_mismatched"`
	PerTag      []tagCheck          `json:"per_tag"`
	Online      []string            `json:"online_commands,omitempty"`
	OK          bool                `json:"ok"`
}

// checkRecords verifies the records offline: every tag chain, the diff chain
// and the snapshots it names, and which tags an attestation sidecar covers.
func checkRecords(records string, online bool) (*recordsCheck, error) {
	rc := &recordsCheck{OK: true}
	store := tag.Store{Root: records}
	keys, err := store.Keys()
	if err != nil {
		return nil, err
	}
	if rc.Attestation, err = attest.Check(records); err != nil {
		return nil, err
	}
	for _, k := range keys {
		h, err := store.History(k.DrillID, k.TargetSlug)
		if err != nil {
			return nil, err
		}
		if len(h) == 0 {
			continue
		}
		rc.Histories++
		st := tag.VerifyChain(h)
		rc.Redacted += st.Redacted
		for _, why := range st.Tampered {
			rc.ChainBroken = append(rc.ChainBroken, k.DrillID+" "+k.TargetSlug+": "+why)
		}
		for _, t := range h {
			rc.Tags++
			rel, _ := filepath.Rel(records, store.PathOf(t.Header))
			state := rc.Attestation.State(rel)
			switch state {
			case attest.Attested:
				rc.Attested++
			case attest.Mismatch:
				rc.Mismatched++
			default:
				rc.Unattested++
			}
			rc.PerTag = append(rc.PerTag, tagCheck{Drill: t.Header.DrillID, Target: t.Header.Target, Stream: t.Header.Stream,
				Time: t.Header.Time.UTC().Format(time.RFC3339), Attestation: state})
		}
	}
	if rc.Diffs, err = run.VerifyDiffs(records); err != nil {
		return nil, err
	}
	if online {
		rc.Online = attest.OnlineCommands(records, rc.Attestation)
	}
	rc.OK = len(rc.ChainBroken) == 0 && rc.Diffs.OK && rc.Mismatched == 0 && len(rc.Attestation.Problems) == 0
	return rc, nil
}

func printRecordsCheck(out io.Writer, rc *recordsCheck) {
	if len(rc.ChainBroken) == 0 {
		fmt.Fprintf(out, "%s  tags: %d histories, %d tags, every chain intact", stylePass.Render("OK"), rc.Histories, rc.Tags)
		if rc.Redacted > 0 {
			fmt.Fprintf(out, " (%d redacted)", rc.Redacted)
		}
		fmt.Fprintln(out)
	} else {
		fmt.Fprintf(out, "%s  tags: %d histories, %d tags, chain broken:\n", styleFail.Render("BROKEN"), rc.Histories, rc.Tags)
		for _, b := range rc.ChainBroken {
			fmt.Fprintln(out, "  "+b)
		}
	}
	d := rc.Diffs
	if d.OK {
		line := fmt.Sprintf("%s  diffs: %d records, chain intact", stylePass.Render("OK"), d.Records)
		if d.Legacy > 0 {
			line += fmt.Sprintf(" (%d from before the chain)", d.Legacy)
		}
		line += fmt.Sprintf("; %d snapshot files match their recorded hash", d.Checked)
		if n := len(d.Compacted); n > 0 {
			line += fmt.Sprintf(", %d compacted (folded into the yearly file, so no longer checkable)", n)
		}
		fmt.Fprintln(out, line)
	} else {
		fmt.Fprintf(out, "%s  diffs: %d records:\n", styleFail.Render("BROKEN"), d.Records)
		for _, p := range d.Problems {
			fmt.Fprintln(out, "  "+p)
		}
	}
	head := stylePass.Render("OK")
	if rc.Mismatched > 0 || len(rc.Attestation.Problems) > 0 {
		head = styleFail.Render("BROKEN")
	}
	fmt.Fprintf(out, "%s  attestation: %d attested, %d unattested, %d checksums mismatch\n", head, rc.Attested, rc.Unattested, rc.Mismatched)
	for _, p := range rc.Attestation.Problems {
		fmt.Fprintln(out, "  "+p)
	}
	for _, u := range rc.Attestation.Unclaimed {
		fmt.Fprintf(out, "  %s has no attestation record: its tags show unattested\n", u)
	}
	for _, t := range rc.PerTag {
		fmt.Fprintf(out, "  %-10s %s %s %s\n", t.Attestation, t.Time, t.Drill, firstNonEmpty(t.Target, "global"))
	}
	if rc.Unattested > 0 {
		fmt.Fprintln(out, styleDim.Render("Local runs are never attested. A CI tag is attested when the workflow's attest and record steps ran."))
	}
	if len(rc.Online) > 0 {
		fmt.Fprintln(out, "\nTo check each attestation's signature, run these yourself (Firedrill makes no call):")
		for _, c := range rc.Online {
			fmt.Fprintln(out, "  "+c)
		}
	}
}

// writeGitHubOutput hands a value to later workflow steps. The value is a
// path Firedrill made, so it holds no newline; one that did is refused.
func writeGitHubOutput(name, value string) error {
	path := os.Getenv("GITHUB_OUTPUT")
	if path == "" || value == "" {
		return nil
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("refusing to write a value with a newline to GITHUB_OUTPUT")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%s=%s\n", name, value); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func printJSON(out io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(b))
	return err
}
