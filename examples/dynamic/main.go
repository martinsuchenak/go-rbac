// Package main demonstrates wildcard permissions, dynamic role loading
// and hot-reload, strict mode, and inline Guard usage.
//
// Run with: go run ./examples/dynamic
package main

import (
	"context"
	"fmt"

	rbac "github.com/martinsuchenak/go-rbac"
	mw "github.com/martinsuchenak/go-rbac/middleware"
)

type AppUser struct {
	Name  string
	roles []rbac.Role
}

func (u *AppUser) GetRoles() []rbac.Role { return u.roles }

// ---------------------------------------------------------------------------
// 1. Wildcard permissions
// ---------------------------------------------------------------------------

func demoWildcards() {
	fmt.Println("=== Wildcard Permissions ===")

	mgr := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"publisher": {
			Permissions: []rbac.Permission{"posts:*"},
		},
		"superadmin": {
			Permissions: []rbac.Permission{"*"},
		},
		"viewer": {
			Permissions: []rbac.Permission{"posts:read"},
		},
	})

	pub := &AppUser{Name: "Publisher", roles: []rbac.Role{"publisher"}}
	god := &AppUser{Name: "SuperAdmin", roles: []rbac.Role{"superadmin"}}
	view := &AppUser{Name: "Viewer", roles: []rbac.Role{"viewer"}}

	fmt.Printf("  publisher can posts:read:   %v\n", mgr.Can(pub, "posts:read"))
	fmt.Printf("  publisher can posts:delete:  %v\n", mgr.Can(pub, "posts:delete"))
	fmt.Printf("  publisher can users:read:    %v\n", mgr.Can(pub, "users:read"))
	fmt.Printf("  superadmin can anything:     %v\n", mgr.Can(god, "literally:anything"))

	fmt.Println()
	fmt.Println("  Wildcards in AllPermissions:")
	fmt.Printf("    publisher → %v\n", mgr.AllPermissions(pub))
	fmt.Printf("    superadmin → %v\n", mgr.AllPermissions(god))
	fmt.Printf("    viewer → %v\n", mgr.AllPermissions(view))

	fmt.Println()
	fmt.Println("  PermissionExists checks:")
	fmt.Printf("    posts:archive exists: %v\n", mgr.PermissionExists("posts:archive"))
	fmt.Printf("    secret:stuff exists:  %v\n", mgr.PermissionExists("secret:stuff"))
}

// ---------------------------------------------------------------------------
// 2. Dynamic role loading with RoleLoader
// ---------------------------------------------------------------------------

func demoDynamicRoles() {
	fmt.Println()
	fmt.Println("=== Dynamic Role Loading ===")

	loadCount := 0
	loader := rbac.RoleLoaderFunc(func(_ context.Context) (map[rbac.Role]rbac.RoleDefinition, error) {
		loadCount++
		if loadCount == 1 {
			return map[rbac.Role]rbac.RoleDefinition{
				"viewer": {Permissions: []rbac.Permission{"posts:read"}},
				"editor": {Permissions: []rbac.Permission{"posts:read", "posts:write"}},
			}, nil
		}
		return map[rbac.Role]rbac.RoleDefinition{
			"viewer": {Permissions: []rbac.Permission{"posts:read"}},
			"editor": {Permissions: []rbac.Permission{"posts:read", "posts:write", "posts:delete"}},
			"manager": {
				Permissions: []rbac.Permission{"users:read"},
				Inherits:    []rbac.Role{"editor"},
			},
		}, nil
	})

	mgr, err := rbac.NewFromLoader(context.Background(), loader)
	if err != nil {
		panic(err)
	}

	user := &AppUser{Name: "Alice", roles: []rbac.Role{"editor"}}
	fmt.Printf("  Initial load: editor can posts:delete: %v\n", mgr.Can(user, "posts:delete"))
	fmt.Printf("  Initial roles: %v\n", mgr.Roles())

	if err := mgr.RebuildFromLoader(context.Background(), loader); err != nil {
		panic(err)
	}

	fmt.Printf("  After reload: editor can posts:delete: %v\n", mgr.Can(user, "posts:delete"))
	fmt.Printf("  After reload: roles: %v\n", mgr.Roles())

	managerUser := &AppUser{Name: "Bob", roles: []rbac.Role{"manager"}}
	fmt.Printf("  Manager inherits editor perms: %v\n", mgr.Can(managerUser, "posts:write"))
}

// ---------------------------------------------------------------------------
// 3. Strict mode and ValidateUser
// ---------------------------------------------------------------------------

func demoStrictMode() {
	fmt.Println()
	fmt.Println("=== Strict Mode & ValidateUser ===")

	mgr := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"viewer": {Permissions: []rbac.Permission{"posts:read"}},
	})

	goodUser := &AppUser{Name: "Alice", roles: []rbac.Role{"viewer"}}
	badUser := &AppUser{Name: "Eve", roles: []rbac.Role{"viewer", "hacker"}}

	unknown := mgr.ValidateUser(badUser)
	fmt.Printf("  ValidateUser(badUser) → %v\n", unknown)
	fmt.Printf("  ValidateUser(goodUser) → %v\n", mgr.ValidateUser(goodUser))

	fmt.Println()
	fmt.Println("  Strict mode panics on unknown roles (dev/test only):")

	strictMgr := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"viewer": {Permissions: []rbac.Permission{"posts:read"}},
	}, rbac.WithStrictMode())

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("  Caught expected panic: %v\n", r)
		}
	}()
	_ = strictMgr.Can(badUser, "posts:read")
}

// ---------------------------------------------------------------------------
// 4. Inline Guard in handler-like code
// ---------------------------------------------------------------------------

func demoGuard() {
	fmt.Println()
	fmt.Println("=== Inline Guard ===")

	mgr := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"editor": {Permissions: []rbac.Permission{"posts:read", "posts:write"}},
		"viewer": {Permissions: []rbac.Permission{"posts:read"}},
	})

	editor := &AppUser{Name: "Editor", roles: []rbac.Role{"editor"}}
	viewer := &AppUser{Name: "Viewer", roles: []rbac.Role{"viewer"}}

	for _, u := range []*AppUser{editor, viewer} {
		if mgr.Can(u, "posts:write") {
			fmt.Printf("  %s: write allowed\n", u.Name)
		} else {
			fmt.Printf("  %s: write denied\n", u.Name)
		}
	}

	fmt.Println()
	fmt.Println("  RoleExists / PermissionExists:")
	fmt.Printf("    editor role exists:    %v\n", mgr.RoleExists("editor"))
	fmt.Printf("    deleted role exists:   %v\n", mgr.RoleExists("deleted"))
	fmt.Printf("    posts:write exists:    %v\n", mgr.PermissionExists("posts:write"))
	fmt.Printf("    posts:delete exists:   %v\n", mgr.PermissionExists("posts:delete"))
}

// ---------------------------------------------------------------------------
// 5. Guard with custom error options (simulated)
// ---------------------------------------------------------------------------

func demoGuardWithOptions() {
	fmt.Println()
	fmt.Println("=== Guard with Options (simulated HTTP) ===")

	mgr := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"admin": {Permissions: []rbac.Permission{"settings:write"}},
	})

	customForbidden := func() {
		fmt.Println("  Custom 403 handler would return JSON: {\"error\": \"forbidden\"}")
	}

	// Simulate Guard behaviour without an actual http.ResponseWriter.
	user := &AppUser{Name: "NonAdmin", roles: []rbac.Role{"viewer"}}
	if !mgr.Can(user, "settings:write") {
		customForbidden()
	}

	admin := &AppUser{Name: "Admin", roles: []rbac.Role{"admin"}}
	if mgr.Can(admin, "settings:write") {
		fmt.Println("  Admin granted access to settings:write")
	}

	_ = mw.Options{
		OnForbidden:    nil,
		OnUnauthorized: nil,
	}
}

func main() {
	demoWildcards()
	demoDynamicRoles()
	demoStrictMode()
	demoGuard()
	demoGuardWithOptions()
}
