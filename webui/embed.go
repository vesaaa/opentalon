// Package webui exposes the embedded frontend filesystem.
// It MUST live at the module root to embed the sibling "web/" directory.
// internal/server/embed.go imports this package to serve static files.
package webui

import "embed"

// FS is the embedded web directory tree.
// The web/dist subdirectory contains the production frontend build.
// The web/index.html is the development skeleton.
//
//go:embed web
var FS embed.FS
