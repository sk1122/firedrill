package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sk1122/firedrill/connector"
	githubconn "github.com/sk1122/firedrill/connectors/github"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/hub"
	"github.com/sk1122/firedrill/internal/run"
)

func hubCmd() *cobra.Command {
	var from string
	c := &cobra.Command{
		Use:   "hub",
		Short: "Search and install open drills from the drill hub",
		Long: "The drill hub is a repo of open drills, each with passing, failing and not-applicable test cases.\n" +
			"Installed drills are copied into .firedrill/drills and recorded in .firedrill/hub.lock, so they stay\n" +
			"reviewable files in your repo. The hub is " + hub.DefaultRepo + " unless hub.repo in config.yaml\n" +
			"or FIREDRILL_HUB names another. Reads use the GitHub connection and are read-only.",
	}
	c.PersistentFlags().StringVar(&from, "from", "", "read the hub from a local folder instead of GitHub")
	load := func(cmd *cobra.Command) (*hub.Hub, string, error) {
		if from != "" {
			h, err := hub.LoadDir(from)
			return h, from, err
		}
		repo, ref := hubSource()
		h, err := fetchHub(cmd.Context(), repo, ref)
		return h, repo, err
	}
	c.AddCommand(hubSearchCmd(load), hubAddCmd(load), hubUpdateCmd(load), hubIndexCmd(), hubSiteCmd())
	return c
}

type hubLoader func(cmd *cobra.Command) (*hub.Hub, string, error)

// hubSource is the hub repo and ref: FIREDRILL_HUB (owner/name[@ref]), then
// config, then the default.
func hubSource() (repo, ref string) {
	repo, ref = hub.DefaultRepo, "main"
	if p, err := config.Load(projectDir); err == nil {
		if p.Config.Hub.Repo != "" {
			repo = p.Config.Hub.Repo
		}
		if p.Config.Hub.Ref != "" {
			ref = p.Config.Hub.Ref
		}
	}
	if v := os.Getenv("FIREDRILL_HUB"); v != "" {
		repo = v
		if r, at, ok := strings.Cut(v, "@"); ok {
			repo, ref = r, at
		}
	}
	return repo, ref
}

// fetchHub downloads the hub at a ref through the guarded GitHub client: one
// GET for the commit, one for the tarball.
func fetchHub(ctx context.Context, repo, ref string) (*hub.Hub, error) {
	if strings.Count(repo, "/") != 1 {
		return nil, fmt.Errorf("hub repo %q must be owner/name", repo)
	}
	conn, ok := connector.Lookup("github")
	if !ok {
		return nil, errors.New("the GitHub connector is missing")
	}
	log := &connector.CallLog{}
	cl := conn.(*githubconn.Connector).HTTP(log)
	token, _ := githubToken(ctx)
	get := func(url, accept string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", accept)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := cl.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound {
				return nil, fmt.Errorf("hub %s@%s not found, or this login cannot read it (run gh auth login, or set FIREDRILL_GITHUB_TOKEN)", repo, ref)
			}
			return nil, fmt.Errorf("hub %s: status %d", repo, resp.StatusCode)
		}
		return resp, nil
	}
	resp, err := get("https://api.github.com/repos/"+repo+"/commits/"+ref, "application/vnd.github.sha")
	if err != nil {
		return nil, err
	}
	shaBytes, err := io.ReadAll(io.LimitReader(resp.Body, 100))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	sha := strings.TrimSpace(string(shaBytes))
	resp, err = get("https://api.github.com/repos/"+repo+"/tarball/"+sha, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	h, err := hub.LoadTarball(resp.Body)
	if err != nil {
		return nil, err
	}
	h.Commit = sha
	return h, nil
}

func hubSearchCmd(load hubLoader) *cobra.Command {
	return &cobra.Command{
		Use:   "search [words]",
		Short: "List hub drills matching every word, or all of them",
		RunE: func(cmd *cobra.Command, args []string) error {
			h, _, err := load(cmd)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			found := h.Search(strings.Join(args, " "))
			lock, _ := hub.ReadLock(projectDir)
			for _, e := range found {
				mark := "  "
				if _, ok := lock.Drills[e.ID]; ok {
					mark = "✓ "
				}
				tagLine := e.Severity
				if e.Official {
					tagLine += ", official"
				}
				if e.Author != "" {
					tagLine += ", " + e.Author
				}
				fmt.Fprintf(out, "%s%-40s %s\n    %s\n", mark, e.ID, tagLine, e.Safeguard)
			}
			fmt.Fprintf(out, "\n%d of %d drills. ✓ installed. Install with: firedrill hub add <id>\n", len(found), len(h.Entries))
			return nil
		},
	}
}

func checkInstallable(e *hub.Entry, h *hub.Hub) error {
	if msg, bad := h.Problems[e.Path]; bad {
		return fmt.Errorf("%s is not installable: %s", e.ID, msg)
	}
	// A local development build is newer than any release.
	if min := e.Drill.MinVersion(); min != "" && run.Version != "dev" && !drill.VersionAtLeast(run.Version, min) {
		return fmt.Errorf("%s needs Firedrill %s or newer; this is %s", e.ID, min, run.Version)
	}
	return nil
}

func hubAddCmd(load hubLoader) *cobra.Command {
	return &cobra.Command{
		Use:   "add <pack/slug>...",
		Short: "Copy hub drills into .firedrill/drills and record them in hub.lock",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(projectDir); err != nil {
				return errors.New("no .firedrill folder here. Run firedrill init first")
			}
			h, repo, err := load(cmd)
			if err != nil {
				return err
			}
			lock, err := hub.ReadLock(projectDir)
			if err != nil {
				return err
			}
			lock.Hub = repo
			out := cmd.OutOrStdout()
			for _, id := range args {
				e, ok := h.Get(id)
				if !ok {
					return fmt.Errorf("%s is not in the hub. Try firedrill hub search", id)
				}
				if err := checkInstallable(e, h); err != nil {
					return err
				}
				path := hub.DrillPath(projectDir, id)
				if local, err := os.ReadFile(path); err == nil {
					if drill.Hash(local) == e.SHA256 {
						fmt.Fprintf(out, "%s is already installed and current.\n", id)
						lock.Drills[id] = hub.LockEntry{Source: "hub", Commit: h.Commit, SHA256: e.SHA256}
						continue
					}
					return fmt.Errorf("%s already exists and differs from the hub. Run firedrill hub update to see the difference", path)
				}
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(path, e.Source, 0o644); err != nil {
					return err
				}
				lock.Drills[id] = hub.LockEntry{Source: "hub", Commit: h.Commit, SHA256: e.SHA256}
				fmt.Fprintf(out, "Added %s (%s).\n", id, e.Safeguard)
			}
			if err := hub.WriteLock(projectDir, lock); err != nil {
				return err
			}
			fmt.Fprintln(out, "Review the drill files, commit them with hub.lock, then run firedrill run.")
			return nil
		},
	}
}

func hubUpdateCmd(load hubLoader) *cobra.Command {
	var yes, force bool
	c := &cobra.Command{
		Use:   "update",
		Short: "Show what changed in the hub for your installed drills, and offer new official drills",
		Long: "For each drill in hub.lock whose hub version changed, prints the difference and asks before\n" +
			"replacing it. A drill you edited since it was installed is left alone unless --force is given.\n" +
			"Official drills you do not have yet are offered too.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := os.Stat(projectDir); err != nil {
				return errors.New("no .firedrill folder here. Run firedrill init first")
			}
			h, repo, err := load(cmd)
			if err != nil {
				return err
			}
			lock, err := hub.ReadLock(projectDir)
			if err != nil {
				return err
			}
			lock.Hub = repo
			out := cmd.OutOrStdout()
			in := bufio.NewReader(cmd.InOrStdin())
			ask := func(q string) bool {
				if yes {
					return true
				}
				fmt.Fprintf(out, "%s [y/N] ", q)
				line, _ := in.ReadString('\n')
				return strings.EqualFold(strings.TrimSpace(line), "y") || strings.EqualFold(strings.TrimSpace(line), "yes")
			}
			ids := make([]string, 0, len(lock.Drills))
			for id := range lock.Drills {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			changed, current, skipped := 0, 0, 0
			for _, id := range ids {
				le := lock.Drills[id]
				e, ok := h.Get(id)
				if !ok {
					continue
				}
				path := hub.DrillPath(projectDir, id)
				local, err := os.ReadFile(path)
				if err != nil {
					continue // removed on purpose
				}
				if drill.Hash(local) == e.SHA256 {
					current++
					lock.Drills[id] = hub.LockEntry{Source: le.Source, Commit: h.Commit, SHA256: e.SHA256}
					continue
				}
				if drill.Hash(local) != le.SHA256 && !force {
					fmt.Fprintf(out, "%s: you edited it since it was installed, so it is left alone. --force replaces it.\n", id)
					skipped++
					continue
				}
				if err := checkInstallable(e, h); err != nil {
					fmt.Fprintf(out, "%s: %v\n", id, err)
					skipped++
					continue
				}
				fmt.Fprintf(out, "\n%s changed in the hub:\n%s", id, hub.Diff(string(local), string(e.Source)))
				if !ask("Replace " + id + "?") {
					skipped++
					continue
				}
				if err := os.WriteFile(path, e.Source, 0o644); err != nil {
					return err
				}
				lock.Drills[id] = hub.LockEntry{Source: "hub", Commit: h.Commit, SHA256: e.SHA256}
				changed++
			}
			added := 0
			for _, e := range h.Entries {
				if !e.Official {
					continue
				}
				if _, ok := lock.Drills[e.ID]; ok {
					continue
				}
				path := hub.DrillPath(projectDir, e.ID)
				if _, err := os.Stat(path); err == nil {
					continue
				}
				if checkInstallable(e, h) != nil {
					continue
				}
				fmt.Fprintf(out, "\nNew official drill %s: %s\n", e.ID, e.Safeguard)
				if !ask("Add " + e.ID + "?") {
					continue
				}
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(path, e.Source, 0o644); err != nil {
					return err
				}
				lock.Drills[e.ID] = hub.LockEntry{Source: "hub", Commit: h.Commit, SHA256: e.SHA256}
				added++
			}
			if err := hub.WriteLock(projectDir, lock); err != nil {
				return err
			}
			fmt.Fprintf(out, "\n%d replaced, %d added, %d current, %d left alone.\n", changed, added, current, skipped)
			return nil
		},
	}
	c.Flags().BoolVar(&yes, "yes", false, "replace and add without asking")
	c.Flags().BoolVar(&force, "force", false, "replace drills you edited, too")
	return c
}

func hubIndexCmd() *cobra.Command {
	var outFile string
	c := &cobra.Command{
		Use:   "index <hub folder>",
		Short: "For hub maintainers: check every drill and its fixtures, and write index.json",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := hub.LoadDir(args[0])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, p := range run.SortedKeys(h.Problems) {
				fmt.Fprintf(out, "FAIL  %s: %s\n", p, h.Problems[p])
			}
			if err := hub.WriteIndex(outFile, hub.BuildIndex(h, time.Now())); err != nil {
				return err
			}
			cases := 0
			for _, e := range h.Entries {
				cases += e.Cases
			}
			fmt.Fprintf(out, "%d drills, %d test cases, %d with problems. Wrote %s\n", len(h.Entries), cases, len(h.Problems), outFile)
			if len(h.Problems) > 0 {
				return exitError{1}
			}
			return nil
		},
	}
	c.Flags().StringVar(&outFile, "out", "index.json", "where to write the index")
	return c
}

func hubSiteCmd() *cobra.Command {
	var outDir string
	c := &cobra.Command{
		Use:   "site <hub folder>",
		Short: "For hub maintainers: build the hub's static website",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			h, err := hub.LoadDir(args[0])
			if err != nil {
				return err
			}
			if err := hub.WriteSite(outDir, h, time.Now()); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s with %d drill pages.\n", filepath.Join(outDir, "index.html"), len(h.Entries))
			return nil
		},
	}
	c.Flags().StringVar(&outDir, "out", "site", "where to write the website")
	return c
}
