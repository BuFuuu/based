// Package collectors holds every scan phase. To add a check (for example
// persistence locations or network listeners), implement scan.Collector in a
// new file and append it to All. Views pick up new finding kinds
// automatically.
package collectors

import "github.com/BuFuuu/based/internal/scan"

func All() []scan.Collector {
	return []scan.Collector{
		&PacmanDB{},
		&SystemFiles{},
		&HomeFiles{},
		&TempFiles{},
		&Packages{},
		&Persistence{},
		&Network{},
	}
}

// HomePart is what the helper of a root scan runs as the user: the package
// database (the home phases compare against it), the home, and the
// persistence kept in it.
func HomePart() []scan.Collector {
	return []scan.Collector{
		&PacmanDB{},
		&HomeFiles{},
		&Persistence{},
	}
}
