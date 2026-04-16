// Package main demonstrates the core RBAC API without any HTTP layer.
//
// Run with: go run ./examples/basic
package main

import (
	"fmt"

	rbac "github.com/martinsuchenak/go-rbac"
)

// ---------------------------------------------------------------------------
// 1. Define roles and permissions as typed constants in your application.
//    This gives you compile-time safety and IDE completion.
// ---------------------------------------------------------------------------

type Role = rbac.Role
type Permission = rbac.Permission

const (
	RoleViewer     Role = "viewer"
	RoleEditor     Role = "editor"
	RoleModerator  Role = "moderator"
	RoleAdmin      Role = "admin"
	RoleSuperAdmin Role = "superadmin"
)

const (
	PermPostsRead     Permission = "posts:read"
	PermPostsWrite    Permission = "posts:write"
	PermPostsDelete   Permission = "posts:delete"
	PermCommentsDelete Permission = "comments:delete"
	PermUsersRead     Permission = "users:read"
	PermUsersWrite    Permission = "users:write"
	PermSettingsWrite Permission = "settings:write"
)

// ---------------------------------------------------------------------------
// 2. Implement the rbac.User interface on your existing user struct.
// ---------------------------------------------------------------------------

// AppUser represents an authenticated user in the application.
type AppUser struct {
	ID    int
	Name  string
	Email string
	roles []rbac.Role
}

// GetRoles satisfies the rbac.User interface.
func (u *AppUser) GetRoles() []rbac.Role { return u.roles }

// AssignRole adds a role to the user (application-level helper).
func (u *AppUser) AssignRole(role rbac.Role) { u.roles = append(u.roles, role) }

// ---------------------------------------------------------------------------
// 3. Configure the RBAC manager at application startup.
// ---------------------------------------------------------------------------

func buildManager() *rbac.Manager {
	return rbac.New(map[rbac.Role]rbac.RoleDefinition{
		RoleViewer: {
			Permissions: []rbac.Permission{PermPostsRead},
		},
		RoleEditor: {
			Permissions: []rbac.Permission{PermPostsRead, PermPostsWrite},
		},
		RoleModerator: {
			// Moderators can delete comments AND everything an editor can do.
			Permissions: []rbac.Permission{PermCommentsDelete},
			Inherits:    []rbac.Role{RoleEditor},
		},
		RoleAdmin: {
			// Admins manage users AND inherit all moderator/editor permissions.
			Permissions: []rbac.Permission{PermUsersRead, PermUsersWrite, PermPostsDelete},
			Inherits:    []rbac.Role{RoleModerator},
		},
		RoleSuperAdmin: {
			// Superadmins can touch settings AND have every admin permission.
			Permissions: []rbac.Permission{PermSettingsWrite},
			Inherits:    []rbac.Role{RoleAdmin},
		},
	})
}

func main() {
	manager := buildManager()

	// Create some users and assign roles.
	alice := &AppUser{ID: 1, Name: "Alice"}
	alice.AssignRole(RoleViewer)

	bob := &AppUser{ID: 2, Name: "Bob"}
	bob.AssignRole(RoleEditor)

	carol := &AppUser{ID: 3, Name: "Carol"}
	carol.AssignRole(RoleAdmin)

	dave := &AppUser{ID: 4, Name: "Dave"}
	dave.AssignRole(RoleModerator)
	dave.AssignRole(RoleViewer) // Dave has two roles simultaneously.

	eve := &AppUser{ID: 5, Name: "Eve"}
	eve.AssignRole(RoleSuperAdmin)

	users := []*AppUser{alice, bob, carol, dave, eve}

	// ---------------------------------------------------------------------------
	// 4. Check permissions throughout application logic.
	// ---------------------------------------------------------------------------

	fmt.Println("=== Permission Checks ===")
	fmt.Println()

	checkPerms := []rbac.Permission{
		PermPostsRead, PermPostsWrite, PermPostsDelete,
		PermCommentsDelete, PermUsersWrite, PermSettingsWrite,
	}

	// Print a table header.
	fmt.Printf("%-10s", "User")
	for _, p := range checkPerms {
		fmt.Printf("  %-18s", p)
	}
	fmt.Println()
	fmt.Printf("%-10s", "----------")
	for range checkPerms {
		fmt.Printf("  %-18s", "------------------")
	}
	fmt.Println()

	for _, u := range users {
		fmt.Printf("%-10s", u.Name)
		for _, p := range checkPerms {
			if manager.Can(u, p) {
				fmt.Printf("  %-18s", "✓")
			} else {
				fmt.Printf("  %-18s", "✗")
			}
		}
		fmt.Println()
	}

	// ---------------------------------------------------------------------------
	// 5. Role checks for UI-level visibility.
	// ---------------------------------------------------------------------------

	fmt.Println()
	fmt.Println("=== UI Visibility Checks ===")
	for _, u := range users {
		fmt.Printf("\n%s:\n", u.Name)
		fmt.Printf("  Show 'Edit Post' button?   %v\n", manager.Can(u, PermPostsWrite))
		fmt.Printf("  Show 'Delete Post' button? %v\n", manager.Can(u, PermPostsDelete))
		fmt.Printf("  Show admin panel link?     %v\n", manager.HasRole(u, RoleAdmin) || manager.HasRole(u, RoleSuperAdmin))
		fmt.Printf("  Show settings page?        %v\n", manager.Can(u, PermSettingsWrite))
	}

	// ---------------------------------------------------------------------------
	// 6. Introspection.
	// ---------------------------------------------------------------------------

	fmt.Println()
	fmt.Println("=== Effective Permissions per Role ===")
	for _, role := range manager.Roles() {
		perms := manager.RolePermissions(role)
		fmt.Printf("  %-12s → %v\n", role, perms)
	}

	// ---------------------------------------------------------------------------
	// 7. Multi-permission checks.
	// ---------------------------------------------------------------------------

	fmt.Println()
	fmt.Println("=== Compound Checks ===")

	// CanAll: must have every permission listed.
	fmt.Printf("Carol CanAll(users:read, users:write): %v\n",
		manager.CanAll(carol, PermUsersRead, PermUsersWrite))

	// CanAny: at least one permission matches.
	fmt.Printf("Alice CanAny(posts:write, settings:write): %v\n",
		manager.CanAny(alice, PermPostsWrite, PermSettingsWrite))

	// Cannot: negation convenience.
	fmt.Printf("Bob Cannot(settings:write): %v\n",
		manager.Cannot(bob, PermSettingsWrite))
}
