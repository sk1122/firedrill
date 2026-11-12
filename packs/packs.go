// Package packs embeds the starter drills, so init can copy them.
package packs

import "embed"

// FS holds every starter drill under <pack>/<slug>.drill.yaml.
//
//go:embed change access agent doors code gcp supply recovery keys
var FS embed.FS
