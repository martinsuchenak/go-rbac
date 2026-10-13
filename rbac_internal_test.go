package rbac

import (
	"fmt"
	"testing"
)

func TestResolve_ExceedsMaxDepth(t *testing.T) {
	m := &Manager{
		roles:             make(map[Role]RoleDefinition, maxResolveDepth+2),
		resolvedPerms:     make(map[Role]map[Permission]struct{}),
		resolvedWildcards: make(map[Role][]string),
		knownPerms:        make(map[Permission]struct{}),
	}

	for i := range maxResolveDepth + 2 {
		role := Role(fmt.Sprintf("r%04d", i))
		var inherits []Role
		if i > 0 {
			inherits = []Role{Role(fmt.Sprintf("r%04d", i-1))}
		}
		m.roles[role] = RoleDefinition{
			Permissions: []Permission{Permission(fmt.Sprintf("p%d", i))},
			Inherits:    inherits,
		}
	}

	deepest := Role(fmt.Sprintf("r%04d", maxResolveDepth+1))

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for inheritance depth exceeding limit")
		}
	}()
	m.resolve(deepest, make(map[Role]struct{}), 0)
}
