package ui

import "embed"

// Files contains the static single-page application assets.
//
//go:embed *.html *.js *.css
var Files embed.FS
