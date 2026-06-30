package webui

import (
	"embed"
	"io/fs"
)

//go:embed static
var Assets embed.FS

// FS returns the sub-filesystem of the static files.
func FS() fs.FS {
	sub, err := fs.Sub(Assets, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
