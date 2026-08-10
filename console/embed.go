// Package console carries the built console bundle into the binary.
//
// The package sits here, next to package.json, rather than under internal/,
// because go:embed cannot reach outside the directory holding the directive —
// there is no `//go:embed ../../console/dist`. The alternative was to have the
// Vite build write its output into a Go package somewhere under internal/,
// which would mean `npm run build` writing outside its own package and the
// artifact living apart from the source that produces it. Keeping both here
// costs one small Go file in an otherwise TypeScript directory, which is the
// cheaper of the two surprises.
//
// The bundle is optional at build time. `dist` is tracked with a placeholder so
// the embed directive always matches something, and a build that never ran the
// console build produces a binary whose console role starts, mounts its routes,
// and tells an operator exactly which command is missing. Making the Go build
// depend on npm would mean no Go contributor could build the server without a
// Node toolchain, for an asset most of them never touch.
package console

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var bundle embed.FS

// Assets returns the built bundle rooted at the directory holding index.html.
func Assets() fs.FS {
	sub, err := fs.Sub(bundle, "dist")
	if err != nil {
		// dist is embedded by the directive above, so this cannot fail unless
		// the embed changed shape, which is a compile-time concern.
		panic(err)
	}
	return sub
}

// Built reports whether this binary carries a real bundle rather than the
// placeholder alone.
func Built() bool {
	f, err := Assets().Open("index.html")
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
