package rbac

import (
	"errors"
	"fmt"
	"testing"
)

// deepChain returns maxResolveDepth+2 roles where each inherits the previous,
// which is one level deeper than resolve allows.
func deepChain() map[Role]RoleDefinition {
	defs := make(map[Role]RoleDefinition, maxResolveDepth+2)
	for i := range maxResolveDepth + 2 {
		role := Role(fmt.Sprintf("r%04d", i))
		var inherits []Role
		if i > 0 {
			inherits = []Role{Role(fmt.Sprintf("r%04d", i-1))}
		}
		defs[role] = RoleDefinition{
			Permissions: []Permission{Permission(fmt.Sprintf("p%d", i))},
			Inherits:    inherits,
		}
	}
	return defs
}

func TestBuild_ExceedsMaxDepth(t *testing.T) {
	_, err := (&Manager{}).build(deepChain())
	if !errors.Is(err, ErrInheritanceTooDeep) {
		t.Fatalf("expected ErrInheritanceTooDeep, got %v", err)
	}
}

func TestRebuild_ExceedsMaxDepthKeepsPreviousDefinitions(t *testing.T) {
	m := New(map[Role]RoleDefinition{"admin": {Permissions: []Permission{"x"}}})

	if err := m.Rebuild(deepChain()); !errors.Is(err, ErrInheritanceTooDeep) {
		t.Fatalf("expected ErrInheritanceTooDeep, got %v", err)
	}
	if !m.Can(Roles{"admin"}, "x") {
		t.Error("previous definitions should remain in effect after a failed Rebuild")
	}
}

func TestNew_PanicsOnExceedsMaxDepth(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for inheritance depth exceeding limit")
		}
	}()
	New(deepChain())
}
