//go:build debug

package debug

import "fmt"

func Print(format string, args ...interface{}) {
	fmt.Printf("DEBUG: "+format, args...)
}
