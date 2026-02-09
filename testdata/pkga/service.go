package pkga

// ARCH-001: Circular dependency — pkga imports pkgb.
import (
	"example.com/project/pkgb"
)

func DoSomething() {
	pkgb.Helper()
}
