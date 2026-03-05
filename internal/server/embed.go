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

	// Check whether dist has a real index.html (vs 只有 .gitkeep 或零散资源).
	entries, _ := fs.ReadDir(distFS, ".")
	hasRealFiles := false
	for _, e := range entries {
		if e.Name() == "index.html" {
			hasRealFiles = true
			break
		}
	}

	var staticFS http.FileSystem
	if hasRealFiles {
		staticFS = http.FS(distFS)
	} else {
		// Fall back to web/ skeleton (contains index.html等开发版资源)
		webRoot, _ := fs.Sub(webui.FS, "web")
		staticFS = http.FS(webRoot)
	}

	// Serve static assets (logo 等) 直接从嵌入的文件系统读取
	r.GET("/logo-opentalon.png", func(c *gin.Context) {
		f, err := staticFS.Open("logo-opentalon.png")
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		defer f.Close()
		stat, _ := f.Stat()
		c.DataFromReader(http.StatusOK, stat.Size(), "image/png", f, nil)
	})

	r.GET("/logo-opentalon-light.png", func(c *gin.Context) {
		f, err := staticFS.Open("logo-opentalon-light.png")
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		defer f.Close()
		stat, _ := f.Stat()
		c.DataFromReader(http.StatusOK, stat.Size(), "image/png", f, nil)
	})

	// favicon：浏览器会默认请求 /favicon.ico，这里显式返回 ICO 文件，
	// 避免走 SPA NoRoute 时返回 index.html。
	r.GET("/favicon.ico", func(c *gin.Context) {
		f, err := staticFS.Open("favicon.ico")
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		defer f.Close()
		stat, _ := f.Stat()
		c.DataFromReader(http.StatusOK, stat.Size(), "image/x-icon", f, nil)
	})

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
