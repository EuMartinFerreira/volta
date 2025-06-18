//go:build !debug

package debug

func Print(format string, args ...interface{}) {
	// Completely removed in an ordinary build
}
