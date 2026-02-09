package pkgb

// ARCH-001: Circular dependency — pkgb imports pkga (mutual import).
import (
	"example.com/project/pkga"
)

func Helper() {
	pkga.DoSomething()
}
