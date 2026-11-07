package dns

import (
	"context"
	"os"
	"testing"
)

// TestLiveSystemResolver reads public DNS. Set FIREDRILL_LIVE=1 to run it.
func TestLiveSystemResolver(t *testing.T) {
	if os.Getenv("FIREDRILL_LIVE") == "" {
		t.Skip("set FIREDRILL_LIVE=1 to read public DNS")
	}
	ctx := context.Background()
	target, err := System{}.CNAME(ctx, "www.github.com")
	if err != nil || target == "" {
		t.Fatalf("www.github.com has a CNAME: %q %v", target, err)
	}
	none, err := System{}.CNAME(ctx, "github.com")
	if err != nil || none != "" {
		t.Fatalf("github.com has no CNAME: %q %v", none, err)
	}
	if ok, err := (System{}).Resolves(ctx, "firedrill-does-not-exist.invalid"); err != nil || ok {
		t.Fatalf("got %v %v", ok, err)
	}
}
