package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/martinsuchenak/go-rbac"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// testUser is a minimal User implementation used only in tests.
type testUser struct {
	roles []rbac.Role
}

func (u *testUser) GetRoles() []rbac.Role { return u.roles }

func user(roles ...rbac.Role) *testUser { return &testUser{roles: roles} }

// permStrings converts []Permission to []string for easier comparison.
func permStrings(perms []rbac.Permission) []string {
	s := make([]string, len(perms))
	for i, p := range perms {
		s[i] = string(p)
	}
	sort.Strings(s)
	return s
}

// roleStrings converts []Role to []string.
func roleStrings(roles []rbac.Role) []string {
	s := make([]string, len(roles))
	for i, r := range roles {
		s[i] = string(r)
	}
	sort.Strings(s)
	return s
}

// stringsEqual returns true if two string slices contain the same elements.
func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Role definitions shared across tests
// ---------------------------------------------------------------------------

func standardManager() *rbac.Manager {
	return rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"viewer": {
			Permissions: []rbac.Permission{"posts:read"},
		},
		"editor": {
			Permissions: []rbac.Permission{"posts:read", "posts:write"},
		},
		"moderator": {
			Permissions: []rbac.Permission{"comments:delete"},
			Inherits:    []rbac.Role{"editor"},
		},
		"admin": {
			Permissions: []rbac.Permission{"users:read", "users:write"},
			Inherits:    []rbac.Role{"moderator"},
		},
		"superadmin": {
			Permissions: []rbac.Permission{"settings:write"},
			Inherits:    []rbac.Role{"admin"},
		},
	})
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestNew_PanicsOnNilRoles(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil roles map, got none")
		}
	}()
	rbac.New(nil)
}

func TestNew_EmptyRolesIsValid(t *testing.T) {
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{})
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

// ---------------------------------------------------------------------------
// Can / Cannot
// ---------------------------------------------------------------------------

func TestCan_DirectPermission(t *testing.T) {
	m := standardManager()

	cases := []struct {
		name       string
		user       rbac.User
		permission rbac.Permission
		want       bool
	}{
		{"viewer can read posts", user("viewer"), "posts:read", true},
		{"viewer cannot write posts", user("viewer"), "posts:write", false},
		{"editor can write posts", user("editor"), "posts:write", true},
		{"editor can read posts", user("editor"), "posts:read", true},
		{"editor cannot manage users", user("editor"), "users:write", false},
		{"admin can manage users", user("admin"), "users:write", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := m.Can(tc.user, tc.permission)
			if got != tc.want {
				t.Errorf("Can(%v) = %v, want %v", tc.permission, got, tc.want)
			}
		})
	}
}

func TestCan_InheritedPermissions(t *testing.T) {
	m := standardManager()

	// moderator inherits editor → can read and write posts
	mod := user("moderator")
	if !m.Can(mod, "posts:read") {
		t.Error("moderator should inherit posts:read from editor")
	}
	if !m.Can(mod, "posts:write") {
		t.Error("moderator should inherit posts:write from editor")
	}
	if !m.Can(mod, "comments:delete") {
		t.Error("moderator should have direct comments:delete")
	}

	// admin inherits moderator → editor chain
	admin := user("admin")
	if !m.Can(admin, "posts:read") {
		t.Error("admin should inherit posts:read transitively")
	}
	if !m.Can(admin, "comments:delete") {
		t.Error("admin should inherit comments:delete from moderator")
	}
	if !m.Can(admin, "users:write") {
		t.Error("admin should have direct users:write")
	}

	// superadmin inherits everything
	sa := user("superadmin")
	for _, perm := range []rbac.Permission{
		"settings:write", "users:read", "users:write",
		"comments:delete", "posts:read", "posts:write",
	} {
		if !m.Can(sa, perm) {
			t.Errorf("superadmin should have permission %q", perm)
		}
	}
}

func TestCan_MultipleRoles(t *testing.T) {
	m := standardManager()
	// User with both viewer and moderator roles.
	u := user("viewer", "moderator")
	if !m.Can(u, "posts:read") {
		t.Error("expected posts:read via viewer or moderator")
	}
	if !m.Can(u, "comments:delete") {
		t.Error("expected comments:delete via moderator")
	}
	// Neither viewer nor moderator has users:write.
	if m.Can(u, "users:write") {
		t.Error("expected no users:write for viewer+moderator")
	}
}

func TestCan_UnknownPermission(t *testing.T) {
	m := standardManager()
	if m.Can(user("admin"), "nonexistent:perm") {
		t.Error("expected false for unknown permission")
	}
}

func TestCan_UnknownRole(t *testing.T) {
	m := standardManager()
	if m.Can(user("ghost"), "posts:read") {
		t.Error("expected false for unknown role")
	}
}

func TestCannot(t *testing.T) {
	m := standardManager()
	if m.Cannot(user("editor"), "posts:write") {
		t.Error("Cannot should return false when user has permission")
	}
	if !m.Cannot(user("viewer"), "posts:write") {
		t.Error("Cannot should return true when user lacks permission")
	}
}

// ---------------------------------------------------------------------------
// CanAll / CanAny
// ---------------------------------------------------------------------------

func TestCanAll(t *testing.T) {
	m := standardManager()
	admin := user("admin")

	if !m.CanAll(admin, "users:read", "users:write", "posts:read") {
		t.Error("admin should have all listed permissions")
	}
	if m.CanAll(admin, "users:read", "settings:write") {
		t.Error("admin should not have settings:write")
	}
}

func TestCanAll_EmptyPermissions(t *testing.T) {
	m := standardManager()
	// Vacuously true — user has all zero required permissions.
	if !m.CanAll(user("viewer")) {
		t.Error("CanAll with no permissions should be true")
	}
}

func TestCanAny(t *testing.T) {
	m := standardManager()
	viewer := user("viewer")

	if !m.CanAny(viewer, "posts:read", "posts:write") {
		t.Error("viewer has posts:read so CanAny should be true")
	}
	if m.CanAny(viewer, "posts:write", "users:read") {
		t.Error("viewer has neither posts:write nor users:read")
	}
}

func TestCanAny_EmptyPermissions(t *testing.T) {
	m := standardManager()
	// Vacuously false — none of the zero required permissions are held.
	if m.CanAny(user("admin")) {
		t.Error("CanAny with no permissions should be false")
	}
}

// ---------------------------------------------------------------------------
// HasRole / HasAnyRole / HasAllRoles
// ---------------------------------------------------------------------------

func TestHasRole(t *testing.T) {
	m := standardManager()
	u := user("editor", "moderator")

	if !m.HasRole(u, "editor") {
		t.Error("user should have editor role")
	}
	if !m.HasRole(u, "moderator") {
		t.Error("user should have moderator role")
	}
	if m.HasRole(u, "admin") {
		t.Error("user should not have admin role (even though moderator inherits from it — HasRole checks direct assignment)")
	}
}

func TestHasAnyRole(t *testing.T) {
	m := standardManager()
	u := user("viewer")

	if !m.HasAnyRole(u, "viewer", "admin") {
		t.Error("user has viewer so HasAnyRole should be true")
	}
	if m.HasAnyRole(u, "admin", "superadmin") {
		t.Error("user has neither admin nor superadmin")
	}
}

func TestHasAllRoles(t *testing.T) {
	m := standardManager()
	u := user("editor", "moderator")

	if !m.HasAllRoles(u, "editor", "moderator") {
		t.Error("user has both roles")
	}
	if m.HasAllRoles(u, "editor", "admin") {
		t.Error("user does not have admin")
	}
}

// ---------------------------------------------------------------------------
// Introspection
// ---------------------------------------------------------------------------

func TestAllPermissions(t *testing.T) {
	m := standardManager()

	// viewer: only posts:read
	got := permStrings(m.AllPermissions(user("viewer")))
	want := []string{"posts:read"}
	if !stringsEqual(got, want) {
		t.Errorf("viewer AllPermissions = %v, want %v", got, want)
	}

	// superadmin: all permissions from the chain
	got = permStrings(m.AllPermissions(user("superadmin")))
	want = []string{"comments:delete", "posts:read", "posts:write", "settings:write", "users:read", "users:write"}
	if !stringsEqual(got, want) {
		t.Errorf("superadmin AllPermissions = %v, want %v", got, want)
	}
}

func TestAllPermissions_MultiRole(t *testing.T) {
	m := standardManager()
	// viewer + moderator should union their effective permissions
	got := permStrings(m.AllPermissions(user("viewer", "moderator")))
	// viewer: posts:read; moderator: comments:delete + inherited posts:read, posts:write
	want := []string{"comments:delete", "posts:read", "posts:write"}
	if !stringsEqual(got, want) {
		t.Errorf("viewer+moderator AllPermissions = %v, want %v", got, want)
	}
}

func TestRolePermissions(t *testing.T) {
	m := standardManager()

	got := permStrings(m.RolePermissions("moderator"))
	want := []string{"comments:delete", "posts:read", "posts:write"}
	if !stringsEqual(got, want) {
		t.Errorf("RolePermissions(moderator) = %v, want %v", got, want)
	}
}

func TestRolePermissions_UnknownRole(t *testing.T) {
	m := standardManager()
	got := m.RolePermissions("ghost")
	if got != nil {
		t.Errorf("expected nil for unknown role, got %v", got)
	}
}

func TestRoles(t *testing.T) {
	m := standardManager()
	got := roleStrings(m.Roles())
	want := []string{"admin", "editor", "moderator", "superadmin", "viewer"}
	if !stringsEqual(got, want) {
		t.Errorf("Roles() = %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// Cycle detection
// ---------------------------------------------------------------------------

func TestCyclicInheritance_TwoWay(t *testing.T) {
	// a → b → a  (2-way cycle)
	// Map iteration order is randomised, so either role may be resolved first.
	// Both must end up with both permissions regardless of order.
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"a": {Permissions: []rbac.Permission{"perm:a"}, Inherits: []rbac.Role{"b"}},
		"b": {Permissions: []rbac.Permission{"perm:b"}, Inherits: []rbac.Role{"a"}},
	})

	for _, role := range []rbac.Role{"a", "b"} {
		u := user(role)
		if !m.Can(u, "perm:a") {
			t.Errorf("role %q should have perm:a", role)
		}
		if !m.Can(u, "perm:b") {
			t.Errorf("role %q should have perm:b", role)
		}
	}
}

func TestCyclicInheritance_ThreeWay(t *testing.T) {
	// a → b → c → a  (3-way cycle)
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"a": {Permissions: []rbac.Permission{"perm:a"}, Inherits: []rbac.Role{"b"}},
		"b": {Permissions: []rbac.Permission{"perm:b"}, Inherits: []rbac.Role{"c"}},
		"c": {Permissions: []rbac.Permission{"perm:c"}, Inherits: []rbac.Role{"a"}},
	})

	for _, role := range []rbac.Role{"a", "b", "c"} {
		u := user(role)
		for _, perm := range []rbac.Permission{"perm:a", "perm:b", "perm:c"} {
			if !m.Can(u, perm) {
				t.Errorf("role %q should have %q (3-way cycle)", role, perm)
			}
		}
	}
}

func TestCyclicInheritance_WithWildcard(t *testing.T) {
	// Cycle with a wildcard to ensure relaxation propagates wildcards too.
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"a": {Permissions: []rbac.Permission{"posts:*"}, Inherits: []rbac.Role{"b"}},
		"b": {Permissions: []rbac.Permission{"users:read"}, Inherits: []rbac.Role{"a"}},
	})

	// Both roles should get the wildcard AND the exact perm.
	for _, role := range []rbac.Role{"a", "b"} {
		u := user(role)
		if !m.Can(u, "posts:write") {
			t.Errorf("role %q should have posts:write via posts:* wildcard", role)
		}
		if !m.Can(u, "users:read") {
			t.Errorf("role %q should have users:read", role)
		}
	}
}

func TestCyclicInheritance_IsDeterministic(t *testing.T) {
	// Run 50 times to confirm the result is stable regardless of map iteration order.
	defs := map[rbac.Role]rbac.RoleDefinition{
		"x": {Permissions: []rbac.Permission{"perm:x"}, Inherits: []rbac.Role{"y"}},
		"y": {Permissions: []rbac.Permission{"perm:y"}, Inherits: []rbac.Role{"x"}},
	}
	for i := 0; i < 50; i++ {
		m := rbac.New(defs)
		if !m.Can(user("x"), "perm:y") {
			t.Fatalf("iteration %d: x missing perm:y", i)
		}
		if !m.Can(user("y"), "perm:x") {
			t.Fatalf("iteration %d: y missing perm:x", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Unknown inherited role
// ---------------------------------------------------------------------------

func TestInheritance_UnknownParentRole(t *testing.T) {
	// "editor" inherits "ghost" which doesn't exist — should not panic.
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"editor": {
			Permissions: []rbac.Permission{"posts:write"},
			Inherits:    []rbac.Role{"ghost"},
		},
	})
	if !m.Can(user("editor"), "posts:write") {
		t.Error("editor should still have its own permissions")
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestConcurrentReads(t *testing.T) {
	m := standardManager()
	done := make(chan struct{})

	for i := 0; i < 50; i++ {
		go func() {
			u := user("admin")
			_ = m.Can(u, "users:write")
			_ = m.HasRole(u, "admin")
			_ = m.AllPermissions(u)
			_ = m.RolePermissions("admin")
			done <- struct{}{}
		}()
	}

	for i := 0; i < 50; i++ {
		<-done
	}
}

// ---------------------------------------------------------------------------
// Wildcard permissions
// ---------------------------------------------------------------------------

func TestWildcard_DirectGrant(t *testing.T) {
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"publisher": {
			Permissions: []rbac.Permission{"posts:*"},
		},
	})

	u := user("publisher")
	for _, perm := range []rbac.Permission{"posts:read", "posts:write", "posts:delete", "posts:publish"} {
		if !m.Can(u, perm) {
			t.Errorf("publisher should have %q via posts:* wildcard", perm)
		}
	}
	// Wildcard should not bleed into other namespaces.
	if m.Can(u, "users:read") {
		t.Error("publisher should not have users:read via posts:* wildcard")
	}
}

func TestWildcard_SuperWildcard(t *testing.T) {
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"god": {
			Permissions: []rbac.Permission{"*"},
		},
	})

	u := user("god")
	for _, perm := range []rbac.Permission{"posts:read", "users:write", "settings:delete", "anything"} {
		if !m.Can(u, perm) {
			t.Errorf("god role should have %q via * wildcard", perm)
		}
	}
}

func TestWildcard_Inherited(t *testing.T) {
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"base": {
			Permissions: []rbac.Permission{"reports:*"},
		},
		"manager": {
			Inherits: []rbac.Role{"base"},
		},
	})

	// manager inherits the wildcard from base.
	u := user("manager")
	if !m.Can(u, "reports:read") {
		t.Error("manager should inherit reports:read via reports:* wildcard from base")
	}
	if !m.Can(u, "reports:export") {
		t.Error("manager should inherit reports:export via reports:* wildcard from base")
	}
}

func TestWildcard_AppearsInAllPermissions(t *testing.T) {
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"publisher": {
			Permissions: []rbac.Permission{"posts:*", "drafts:read"},
		},
	})

	got := permStrings(m.AllPermissions(user("publisher")))
	want := []string{"drafts:read", "posts:*"}
	if !stringsEqual(got, want) {
		t.Errorf("AllPermissions = %v, want %v", got, want)
	}
}

func TestWildcard_AppearsInRolePermissions(t *testing.T) {
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"publisher": {
			Permissions: []rbac.Permission{"posts:*", "drafts:read"},
		},
	})

	got := permStrings(m.RolePermissions("publisher"))
	want := []string{"drafts:read", "posts:*"}
	if !stringsEqual(got, want) {
		t.Errorf("RolePermissions = %v, want %v", got, want)
	}
}

func TestWildcard_InheritedAppearsInRolePermissions(t *testing.T) {
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"base": {
			Permissions: []rbac.Permission{"reports:*"},
		},
		"manager": {
			Inherits: []rbac.Role{"base"},
		},
	})

	got := permStrings(m.RolePermissions("manager"))
	want := []string{"reports:*"}
	if !stringsEqual(got, want) {
		t.Errorf("RolePermissions(manager) = %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// RoleExists / PermissionExists
// ---------------------------------------------------------------------------

func TestRoleExists(t *testing.T) {
	m := standardManager()

	if !m.RoleExists("admin") {
		t.Error("admin should exist")
	}
	if !m.RoleExists("viewer") {
		t.Error("viewer should exist")
	}
	if m.RoleExists("ghost") {
		t.Error("ghost should not exist")
	}
}

func TestPermissionExists_Exact(t *testing.T) {
	m := standardManager()

	if !m.PermissionExists("posts:read") {
		t.Error("posts:read should exist")
	}
	if !m.PermissionExists("users:write") {
		t.Error("users:write should exist (via admin)")
	}
	if !m.PermissionExists("settings:write") {
		t.Error("settings:write should exist (via superadmin)")
	}
	if m.PermissionExists("nonexistent:perm") {
		t.Error("nonexistent:perm should not exist")
	}
}

func TestPermissionExists_InheritedPermission(t *testing.T) {
	m := standardManager()
	// posts:read is defined on viewer and editor; superadmin inherits it
	// transitively. PermissionExists should find it regardless.
	if !m.PermissionExists("posts:read") {
		t.Error("posts:read should exist (inherited by many roles)")
	}
}

func TestPermissionExists_WildcardCoverage(t *testing.T) {
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"publisher": {
			Permissions: []rbac.Permission{"posts:*"},
		},
	})

	// "posts:anything" should be found because "posts:*" covers it.
	if !m.PermissionExists("posts:archive") {
		t.Error("posts:archive should exist via posts:* wildcard")
	}
	// A different namespace should not be covered.
	if m.PermissionExists("users:read") {
		t.Error("users:read should not exist — not covered by posts:*")
	}
}

func TestPermissionExists_ExactWildcardString(t *testing.T) {
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"publisher": {
			Permissions: []rbac.Permission{"posts:*"},
		},
	})

	// "posts:*" itself is an exact wildcard grant — should be found.
	if !m.PermissionExists("posts:*") {
		t.Error("posts:* itself should exist as an exact wildcard grant")
	}
	// "*" alone should NOT be found because no role has it.
	if m.PermissionExists("*") {
		t.Error("* should not exist — no role has the * wildcard")
	}
}

// ---------------------------------------------------------------------------
// WithStrictMode / ValidateUser
// ---------------------------------------------------------------------------

func TestStrictMode_PanicsOnUnknownRole(t *testing.T) {
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"admin": {Permissions: []rbac.Permission{"users:write"}},
	}, rbac.WithStrictMode())

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic in strict mode for unknown role, got none")
		}
	}()

	_ = m.Can(user("ghost"), "users:write")
}

func TestStrictMode_DoesNotPanicForKnownRole(t *testing.T) {
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"admin": {Permissions: []rbac.Permission{"users:write"}},
	}, rbac.WithStrictMode())

	// Must not panic.
	if !m.Can(user("admin"), "users:write") {
		t.Error("admin should have users:write")
	}
}

func TestStrictMode_DoesNotPanicForUnknownInherited(t *testing.T) {
	// "editor" inherits "base" which is not separately defined.
	// "base" ends up in resolvedPerms (as an empty entry), so it is considered
	// known and should not panic in strict mode when assigned to a user.
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"editor": {
			Permissions: []rbac.Permission{"posts:write"},
			Inherits:    []rbac.Role{"base"},
		},
	}, rbac.WithStrictMode())

	// "base" was registered implicitly via Inherits — should not panic.
	if m.Can(user("base"), "posts:write") {
		t.Error("base has no permissions, expected false")
	}
}

func TestValidateUser_AllKnown(t *testing.T) {
	m := standardManager()
	unknown := m.ValidateUser(user("admin", "viewer"))
	if len(unknown) != 0 {
		t.Errorf("expected no unknown roles, got %v", unknown)
	}
}

func TestValidateUser_UnknownRoles(t *testing.T) {
	m := standardManager()
	unknown := m.ValidateUser(user("admin", "ghost", "phantom"))
	if len(unknown) != 2 {
		t.Errorf("expected 2 unknown roles, got %v", unknown)
	}
	got := roleStrings(unknown)
	want := []string{"ghost", "phantom"}
	if !stringsEqual(got, want) {
		t.Errorf("unknown roles = %v, want %v", got, want)
	}
}

func TestValidateUser_NeverPanics(t *testing.T) {
	// ValidateUser must not panic regardless of strict mode.
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"admin": {Permissions: []rbac.Permission{"users:write"}},
	}, rbac.WithStrictMode())

	unknown := m.ValidateUser(user("ghost"))
	if len(unknown) != 1 {
		t.Errorf("expected 1 unknown role, got %v", unknown)
	}
}

// ---------------------------------------------------------------------------
// Rebuild
// ---------------------------------------------------------------------------

func TestRebuild_UpdatesPermissions(t *testing.T) {
	m := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"reader": {Permissions: []rbac.Permission{"posts:read"}},
	})

	u := user("reader")
	if !m.Can(u, "posts:read") {
		t.Fatal("reader should have posts:read before rebuild")
	}
	if m.Can(u, "posts:write") {
		t.Fatal("reader should not have posts:write before rebuild")
	}

	// Rebuild with extended permissions.
	m.Rebuild(map[rbac.Role]rbac.RoleDefinition{
		"reader": {Permissions: []rbac.Permission{"posts:read", "posts:write"}},
	})

	if !m.Can(u, "posts:write") {
		t.Error("reader should have posts:write after rebuild")
	}
}

func TestRebuild_RemovesOldRoles(t *testing.T) {
	m := standardManager()

	if !m.RoleExists("superadmin") {
		t.Fatal("superadmin should exist before rebuild")
	}

	m.Rebuild(map[rbac.Role]rbac.RoleDefinition{
		"viewer": {Permissions: []rbac.Permission{"posts:read"}},
	})

	if m.RoleExists("superadmin") {
		t.Error("superadmin should not exist after rebuild")
	}
	if !m.RoleExists("viewer") {
		t.Error("viewer should still exist after rebuild")
	}
}

func TestRebuild_PanicsOnNilRoles(t *testing.T) {
	m := standardManager()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil roles map, got none")
		}
	}()
	m.Rebuild(nil)
}

func TestRebuild_ConcurrentWithReads(t *testing.T) {
	m := standardManager()
	var wg sync.WaitGroup

	// 20 goroutines reading concurrently.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = m.Can(user("admin"), "users:write")
			}
		}()
	}

	// 5 goroutines rebuilding concurrently.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Rebuild(map[rbac.Role]rbac.RoleDefinition{
				"admin": {Permissions: []rbac.Permission{"users:write"}},
			})
		}()
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// NewFromLoader / RebuildFromLoader
// ---------------------------------------------------------------------------

func TestNewFromLoader_Success(t *testing.T) {
	defs := map[rbac.Role]rbac.RoleDefinition{
		"editor": {Permissions: []rbac.Permission{"posts:write"}},
	}
	loader := rbac.RoleLoaderFunc(func(_ context.Context) (map[rbac.Role]rbac.RoleDefinition, error) {
		return defs, nil
	})

	m, err := rbac.NewFromLoader(context.Background(), loader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !m.Can(user("editor"), "posts:write") {
		t.Error("editor should have posts:write after NewFromLoader")
	}
}

func TestNewFromLoader_LoaderError(t *testing.T) {
	sentinel := errors.New("db unavailable")
	loader := rbac.RoleLoaderFunc(func(_ context.Context) (map[rbac.Role]rbac.RoleDefinition, error) {
		return nil, sentinel
	})

	_, err := rbac.NewFromLoader(context.Background(), loader)
	if err == nil {
		t.Fatal("expected error from NewFromLoader, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}

func TestNewFromLoader_NilDefsReturnsError(t *testing.T) {
	loader := rbac.RoleLoaderFunc(func(_ context.Context) (map[rbac.Role]rbac.RoleDefinition, error) {
		return nil, nil
	})

	_, err := rbac.NewFromLoader(context.Background(), loader)
	if err == nil {
		t.Fatal("expected error for nil definitions, got nil")
	}
}

func TestNewFromLoader_AcceptsOptions(t *testing.T) {
	loader := rbac.RoleLoaderFunc(func(_ context.Context) (map[rbac.Role]rbac.RoleDefinition, error) {
		return map[rbac.Role]rbac.RoleDefinition{
			"admin": {Permissions: []rbac.Permission{"users:write"}},
		}, nil
	})

	m, err := rbac.NewFromLoader(context.Background(), loader, rbac.WithStrictMode())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected strict mode panic for unknown role, got none")
		}
	}()
	_ = m.Can(user("ghost"), "users:write")
}

func TestRebuildFromLoader_Success(t *testing.T) {
	m := standardManager()

	newDefs := map[rbac.Role]rbac.RoleDefinition{
		"writer": {Permissions: []rbac.Permission{"posts:write"}},
	}
	loader := rbac.RoleLoaderFunc(func(_ context.Context) (map[rbac.Role]rbac.RoleDefinition, error) {
		return newDefs, nil
	})

	if err := m.RebuildFromLoader(context.Background(), loader); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !m.RoleExists("writer") {
		t.Error("writer should exist after RebuildFromLoader")
	}
	if m.RoleExists("admin") {
		t.Error("admin should not exist after RebuildFromLoader")
	}
}

func TestRebuildFromLoader_LoaderError(t *testing.T) {
	m := standardManager()
	sentinel := errors.New("connection refused")

	loader := rbac.RoleLoaderFunc(func(_ context.Context) (map[rbac.Role]rbac.RoleDefinition, error) {
		return nil, sentinel
	})

	err := m.RebuildFromLoader(context.Background(), loader)
	if err == nil {
		t.Fatal("expected error from RebuildFromLoader, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}

	// Manager should be unchanged on error.
	if !m.RoleExists("admin") {
		t.Error("admin should still exist after failed RebuildFromLoader")
	}
}

// ---------------------------------------------------------------------------
// Max inheritance depth
// ---------------------------------------------------------------------------

func TestResolve_DeepChainSucceeds(t *testing.T) {
	const chainLen = 500
	defs := make(map[rbac.Role]rbac.RoleDefinition, chainLen)
	for i := 0; i < chainLen; i++ {
		role := rbac.Role(fmt.Sprintf("r%04d", i))
		var inherits []rbac.Role
		if i > 0 {
			inherits = []rbac.Role{rbac.Role(fmt.Sprintf("r%04d", i-1))}
		}
		defs[role] = rbac.RoleDefinition{
			Permissions: []rbac.Permission{rbac.Permission(fmt.Sprintf("p%d", i))},
			Inherits:    inherits,
		}
	}

	m := rbac.New(defs)

	u := user(rbac.Role(fmt.Sprintf("r%04d", chainLen-1)))
	if !m.Can(u, rbac.Permission("p0")) {
		t.Error("deepest role should inherit p0 through the chain")
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func benchmarkManager() *rbac.Manager {
	return rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"viewer": {Permissions: []rbac.Permission{"posts:read"}},
		"editor": {Permissions: []rbac.Permission{"posts:read", "posts:write", "posts:delete"}},
		"moderator": {
			Permissions: []rbac.Permission{"posts:moderate"},
			Inherits:    []rbac.Role{"editor"},
		},
		"admin": {
			Permissions: []rbac.Permission{"users:read", "users:write"},
			Inherits:    []rbac.Role{"moderator"},
		},
		"superadmin": {
			Permissions: []rbac.Permission{"*"},
		},
	})
}

func BenchmarkCan_Exact(b *testing.B) {
	m := benchmarkManager()
	u := user("admin")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Can(u, "users:write")
	}
}

func BenchmarkCan_Wildcard(b *testing.B) {
	m := benchmarkManager()
	u := user("superadmin")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Can(u, "anything:here")
	}
}

func BenchmarkCan_Miss(b *testing.B) {
	m := benchmarkManager()
	u := user("viewer")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Can(u, "users:write")
	}
}

func BenchmarkCan_MultiRole(b *testing.B) {
	m := benchmarkManager()
	u := user("admin", "viewer")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Can(u, "posts:read")
	}
}

func BenchmarkCanAll(b *testing.B) {
	m := benchmarkManager()
	u := user("admin")
	perms := []rbac.Permission{"posts:read", "users:write"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.CanAll(u, perms...)
	}
}

func BenchmarkCanAny(b *testing.B) {
	m := benchmarkManager()
	u := user("admin")
	perms := []rbac.Permission{"settings:write", "users:write"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.CanAny(u, perms...)
	}
}

func BenchmarkAllPermissions(b *testing.B) {
	m := benchmarkManager()
	u := user("admin")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.AllPermissions(u)
	}
}

func BenchmarkRebuild(b *testing.B) {
	defs := map[rbac.Role]rbac.RoleDefinition{
		"viewer": {Permissions: []rbac.Permission{"posts:read"}},
		"editor": {Permissions: []rbac.Permission{"posts:read", "posts:write"}},
		"admin": {
			Permissions: []rbac.Permission{"users:write"},
			Inherits:    []rbac.Role{"editor"},
		},
	}
	m := rbac.New(defs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Rebuild(defs)
	}
}

func BenchmarkNew(b *testing.B) {
	defs := map[rbac.Role]rbac.RoleDefinition{
		"viewer": {Permissions: []rbac.Permission{"posts:read"}},
		"editor": {Permissions: []rbac.Permission{"posts:read", "posts:write"}},
		"admin": {
			Permissions: []rbac.Permission{"users:write"},
			Inherits:    []rbac.Role{"editor"},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rbac.New(defs)
	}
}
