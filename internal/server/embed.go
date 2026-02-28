// Package server handles embedding and serving of the frontend UI.
// Static files are embedded via the root-level webui package,
// which can access the sibling web/ directory via go:embed.
package server

import (
	"io/fs"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vesaa/opentalon/webui"
)

// RegisterStaticFiles mounts the embedded frontend on the Gin engine.
// API routes registered before this will take precedence.
// All unmatched routes fall back to index.html for SPA routing.
func RegisterStaticFiles(r *gin.Engine) {
	// Serve files from web/dist (production build) if they have real content,
	// otherwise fall back to web/ (development skeleton).
	distFS, err := fs.Sub(webui.FS, "web/dist")
	if err != nil {
		panic("embed: web/dist sub-fs failed: " + err.Error())
	}

	// Check whether dist has real files (vs just .gitkeep).
	entries, _ := fs.ReadDir(distFS, ".")
	hasRealFiles := false
	for _, e := range entries {
		if e.Name() != ".gitkeep" {
			hasRealFiles = true
			break
		}
	}

	var staticFS http.FileSystem
	if hasRealFiles {
		staticFS = http.FS(distFS)
	} else {
		// Fall back to web/ skeleton (contains index.html)
		webRoot, _ := fs.Sub(webui.FS, "web")
		staticFS = http.FS(webRoot)
	}

	// SPA fallback: ALL unmatched routes return index.html
	r.NoRoute(func(c *gin.Context) {
		f, err := staticFS.Open("index.html")
		if err != nil {
			c.String(http.StatusNotFound, "UI not found — run 'make ui' to build the frontend")
			return
		}
		defer f.Close()
		stat, _ := f.Stat()
		c.DataFromReader(http.StatusOK, stat.Size(), "text/html; charset=utf-8", f, nil)
	})
}
