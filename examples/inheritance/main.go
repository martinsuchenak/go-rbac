// Package main demonstrates deep role inheritance hierarchies, including
// diamond inheritance (a role inheriting from two parents that share a
// common ancestor) and cycle detection.
//
// Run with: go run ./examples/inheritance
package main

import (
	"fmt"

	rbac "github.com/martinsuchenak/go-rbac"
)

// SaaS-style role hierarchy:
//
//	member ──────────────────────────────────────────┐
//	                                                  ↓
//	team_lead → member                           (viewer alias)
//	manager   → team_lead → member
//	director  → manager   → team_lead → member
//	                                          ↑
//	billing_admin → member ──────────────────┘   (diamond)
//	executive     → director + billing_admin      (two parents)

const (
	PermViewDashboard  rbac.Permission = "dashboard:view"
	PermCreateProject  rbac.Permission = "projects:create"
	PermApproveExpense rbac.Permission = "expenses:approve"
	PermHireStaff      rbac.Permission = "staff:hire"
	PermViewBilling    rbac.Permission = "billing:view"
	PermEditBilling    rbac.Permission = "billing:edit"
	PermAccessAllData  rbac.Permission = "data:all"
	PermSystemConfig   rbac.Permission = "system:config"
)

type Employee struct {
	Name  string
	Title string
	roles []rbac.Role
}

func (e *Employee) GetRoles() []rbac.Role { return e.roles }

func newEmployee(name, title string, roles ...rbac.Role) *Employee {
	return &Employee{Name: name, Title: title, roles: roles}
}

func main() {
	// -------------------------------------------------------------------------
	// Build a deep, realistic role hierarchy.
	// -------------------------------------------------------------------------
	mgr := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"member": {
			Permissions: []rbac.Permission{PermViewDashboard},
		},
		"team_lead": {
			Permissions: []rbac.Permission{PermCreateProject},
			Inherits:    []rbac.Role{"member"},
		},
		"manager": {
			Permissions: []rbac.Permission{PermApproveExpense},
			Inherits:    []rbac.Role{"team_lead"},
		},
		"director": {
			Permissions: []rbac.Permission{PermHireStaff},
			Inherits:    []rbac.Role{"manager"},
		},
		"billing_admin": {
			// billing_admin also inherits member — so executive gets a diamond.
			Permissions: []rbac.Permission{PermViewBilling, PermEditBilling},
			Inherits:    []rbac.Role{"member"},
		},
		"executive": {
			// Two parents: director + billing_admin.
			// The library deduplicates permissions from both branches.
			Permissions: []rbac.Permission{PermAccessAllData},
			Inherits:    []rbac.Role{"director", "billing_admin"},
		},
		"sysadmin": {
			Permissions: []rbac.Permission{PermSystemConfig},
			Inherits:    []rbac.Role{"executive"},
		},
	})

	// -------------------------------------------------------------------------
	// Employees at different levels of the hierarchy.
	// -------------------------------------------------------------------------
	employees := []*Employee{
		newEmployee("Sam", "Member", "member"),
		newEmployee("Taylor", "Team Lead", "team_lead"),
		newEmployee("Jordan", "Manager", "manager"),
		newEmployee("Riley", "Director", "director"),
		newEmployee("Alex", "Billing Admin", "billing_admin"),
		newEmployee("Morgan", "Executive", "executive"),
		newEmployee("Casey", "Sysadmin", "sysadmin"),
	}

	allPerms := []rbac.Permission{
		PermViewDashboard,
		PermCreateProject,
		PermApproveExpense,
		PermHireStaff,
		PermViewBilling,
		PermEditBilling,
		PermAccessAllData,
		PermSystemConfig,
	}

	// -------------------------------------------------------------------------
	// Print a permission matrix.
	// -------------------------------------------------------------------------
	fmt.Println("=== Permission Matrix (✓ = has permission) ===")
	fmt.Println()

	// Header
	fmt.Printf("%-22s", "Employee (Title)")
	for _, p := range allPerms {
		fmt.Printf("  %-18s", shortPerm(p))
	}
	fmt.Println()
	sep := "----------------------"
	fmt.Printf("%-22s", sep)
	for range allPerms {
		fmt.Printf("  %-18s", "------------------")
	}
	fmt.Println()

	for _, e := range employees {
		fmt.Printf("%-22s", fmt.Sprintf("%s (%s)", e.Name, e.Title))
		for _, p := range allPerms {
			if mgr.Can(e, p) {
				fmt.Printf("  %-18s", "✓")
			} else {
				fmt.Printf("  %-18s", "·")
			}
		}
		fmt.Println()
	}

	// -------------------------------------------------------------------------
	// Effective permissions per role (sorted, deduplicated).
	// -------------------------------------------------------------------------
	fmt.Println()
	fmt.Println("=== Effective Permissions per Role ===")
	for _, role := range mgr.Roles() {
		perms := mgr.RolePermissions(role)
		fmt.Printf("  %-14s → %v\n", role, perms)
	}

	// -------------------------------------------------------------------------
	// Diamond inheritance — deduplication proof.
	// -------------------------------------------------------------------------
	fmt.Println()
	fmt.Println("=== Diamond Inheritance: executive ===")
	fmt.Println("executive inherits from director AND billing_admin,")
	fmt.Println("both of which inherit from member (via team_lead chain).")
	fmt.Println("dashboard:view should appear exactly once:")
	perms := mgr.AllPermissions(newEmployee("Morgan", "Executive", "executive"))
	fmt.Printf("  AllPermissions → %v\n", perms)

	// -------------------------------------------------------------------------
	// Cycle-safe construction.
	// -------------------------------------------------------------------------
	fmt.Println()
	fmt.Println("=== Cycle Detection ===")
	cyclicMgr := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"alpha": {
			Permissions: []rbac.Permission{"perm:alpha"},
			Inherits:    []rbac.Role{"beta"},
		},
		"beta": {
			Permissions: []rbac.Permission{"perm:beta"},
			Inherits:    []rbac.Role{"gamma"},
		},
		"gamma": {
			Permissions: []rbac.Permission{"perm:gamma"},
			Inherits:    []rbac.Role{"alpha"}, // cycle back to alpha
		},
	})

	u := &Employee{Name: "Cycle Test", roles: []rbac.Role{"alpha"}}
	fmt.Printf("  Cyclic role 'alpha' has perm:alpha: %v\n", cyclicMgr.Can(u, "perm:alpha"))
	fmt.Printf("  Cyclic role 'alpha' has perm:beta:  %v\n", cyclicMgr.Can(u, "perm:beta"))
	fmt.Printf("  Cyclic role 'alpha' has perm:gamma: %v\n", cyclicMgr.Can(u, "perm:gamma"))
	fmt.Println("  (No hang or panic — cycle was detected and broken)")
}

func shortPerm(p rbac.Permission) string {
	// Trim "resource:" prefix for compact table display.
	s := string(p)
	for i, c := range s {
		if c == ':' {
			return s[i+1:]
		}
	}
	return s
}
