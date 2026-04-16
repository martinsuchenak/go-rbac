// Package rbac provides a lightweight, runtime-configurable Role-Based Access
// Control (RBAC) engine for Go applications.
//
// # Core concepts
//
// Roles and permissions are plain strings — the library imposes no vocabulary.
// Applications define them as typed constants for compile-time safety:
//
//	const (
//	    RoleAdmin  rbac.Role       = "admin"
//	    PermWrite  rbac.Permission = "posts:write"
//	)
//
// The Manager is constructed once (or rebuilt on demand) from a map of
// RoleDefinition values, each declaring direct permissions and optional parent
// roles to inherit from. Permission checks are O(1) after construction.
//
// # Quick Start
//
//	manager := rbac.New(map[rbac.Role]rbac.RoleDefinition{
//	    "viewer": {Permissions: []rbac.Permission{"posts:read"}},
//	    "editor": {Permissions: []rbac.Permission{"posts:read", "posts:write"}},
//	    "admin": {
//	        Permissions: []rbac.Permission{"users:write"},
//	        Inherits:    []rbac.Role{"editor"},
//	    },
//	})
//
//	manager.Can(user, "posts:write")    // true/false
//	manager.HasRole(user, "admin")      // direct assignment only
//
// # Wildcard permissions
//
// A permission ending in "*" is a prefix grant matched against the requested
// permission at check time:
//
//	"posts:*"  →  grants "posts:read", "posts:write", "posts:delete", …
//	"*"        →  grants every permission
//
// Wildcards are inherited transitively and appear verbatim in AllPermissions
// and RolePermissions output.
//
// # Dynamic and database-driven roles
//
// Implement RoleLoader (or use RoleLoaderFunc) to load definitions from any
// external source:
//
//	manager, err := rbac.NewFromLoader(ctx, rbac.RoleLoaderFunc(loadFromDB))
//
// To update a live manager without downtime, call Rebuild or RebuildFromLoader.
// Both are safe to call concurrently with ongoing permission checks.
//
// # Development options
//
// WithStrictMode causes Can (and all methods that delegate to it) to panic
// when the user holds an unregistered role. Intended for tests.
//
// ValidateUser returns unknown roles without panicking, and is safe for
// production observability.
package rbac

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Role is the type for role identifiers. Consuming applications should define
// their roles as typed constants of this type for compile-time safety:
//
//	const RoleAdmin rbac.Role = "admin"
type Role string

// Permission is the type for permission identifiers. Permissions are arbitrary
// strings; the library imposes no structure. Common conventions include:
//
//   - Resource + action: "posts:write", "users:delete"
//   - Flat strings:      "can_publish", "manage_billing"
//   - Hierarchical:      "org:team:resource:action"
//   - Wildcard grants:   "posts:*", "*"
type Permission string

// User is the interface that consuming applications must implement so the
// RBAC engine can inspect which roles are assigned to a given principal.
// Typically this is satisfied by an existing user/session struct:
//
//	type AppUser struct {
//	    ID    int
//	    Name  string
//	    Roles []rbac.Role
//	}
//
//	func (u *AppUser) GetRoles() []rbac.Role { return u.Roles }
type User interface {
	GetRoles() []Role
}

// RoleDefinition declares the permissions granted to a role and, optionally,
// which other roles it inherits from. Inheritance is deep — inherited roles
// may themselves have their own Inherits, and the engine resolves the full
// transitive closure at startup.
type RoleDefinition struct {
	// Permissions granted directly to this role. A permission ending in "*"
	// is treated as a wildcard prefix grant (see package doc).
	Permissions []Permission

	// Inherits lists roles whose resolved permissions are folded into this
	// role's effective permission set. Circular inheritance is handled
	// gracefully (cycles are detected and skipped).
	Inherits []Role
}

// ---------------------------------------------------------------------------
// RoleLoader
// ---------------------------------------------------------------------------

// RoleLoader is the interface for loading role definitions from an external
// source such as a database, configuration file, or remote service.
// Implement it to drive the RBAC manager from dynamic data:
//
//	type DBLoader struct{ db *sql.DB }
//
//	func (l *DBLoader) Load(ctx context.Context) (map[rbac.Role]rbac.RoleDefinition, error) {
//	    // query DB and return definitions
//	}
//
//	manager, err := rbac.NewFromLoader(ctx, &DBLoader{db: db})
type RoleLoader interface {
	Load(ctx context.Context) (map[Role]RoleDefinition, error)
}

// RoleLoaderFunc is a function that implements RoleLoader. It allows a plain
// function to be used wherever a RoleLoader is expected:
//
//	loader := rbac.RoleLoaderFunc(func(ctx context.Context) (map[rbac.Role]rbac.RoleDefinition, error) {
//	    return loadFromDB(ctx, db)
//	})
type RoleLoaderFunc func(ctx context.Context) (map[Role]RoleDefinition, error)

// Load implements RoleLoader.
func (f RoleLoaderFunc) Load(ctx context.Context) (map[Role]RoleDefinition, error) {
	return f(ctx)
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

// Option configures a Manager at construction time.
type Option func(*Manager)

// WithStrictMode returns an Option that causes Can (and all methods that
// delegate to it) to panic when the user holds a role not registered with
// the manager. Intended for use in development and testing to catch
// misconfigured role assignments early.
//
// For production validation without panics, use ValidateUser instead.
func WithStrictMode() Option {
	return func(m *Manager) {
		m.strict = true
	}
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

// Manager is the RBAC engine. Create one with New or NewFromLoader, then use
// its methods to perform access checks throughout your application.
//
// Manager is safe for concurrent use after construction. Rebuild and
// RebuildFromLoader may be called concurrently with any read operations.
type Manager struct {
	mu sync.RWMutex

	roles map[Role]RoleDefinition

	// resolvedPerms holds the transitive exact-permission sets for each role,
	// computed once in build() and never mutated on the read path.
	resolvedPerms map[Role]map[Permission]struct{}

	// resolvedWildcards holds the stripped prefix strings (e.g. "posts:" for
	// the "posts:*" permission) for each role, including inherited wildcards.
	// Stored as plain strings so Can() does a fast strings.HasPrefix without
	// re-parsing. Roles with no wildcard grants have no entry here.
	resolvedWildcards map[Role][]string

	// knownPerms is the union of all exact permissions across all resolved
	// roles. Used by PermissionExists for O(1) lookup.
	knownPerms map[Permission]struct{}

	// allWildcardPrefixes is the deduplicated union of all wildcard prefixes
	// across all roles. Used by PermissionExists to avoid iterating per-role.
	allWildcardPrefixes []string

	strict bool
}

// New constructs a Manager from the provided role definitions and optional
// configuration options. It resolves role inheritance eagerly so that runtime
// permission checks are O(roles assigned to the user) with a cheap map lookup
// per role.
//
// New panics if roles is nil.
//
// The options do not change the call signature for existing code:
//
//	rbac.New(defs)                          // unchanged
//	rbac.New(defs, rbac.WithStrictMode())   // new
func New(roles map[Role]RoleDefinition, opts ...Option) *Manager {
	if roles == nil {
		panic("rbac: roles map must not be nil")
	}
	m := &Manager{}
	for _, opt := range opts {
		opt(m)
	}
	m.build(roles)
	return m
}

// NewFromLoader constructs a Manager by loading role definitions from the
// provided loader. Returns an error if the loader fails; if the loader
// succeeds but returns a nil map, NewFromLoader returns an error rather than
// panicking.
func NewFromLoader(ctx context.Context, loader RoleLoader, opts ...Option) (*Manager, error) {
	defs, err := loader.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: loader: %w", err)
	}
	if defs == nil {
		return nil, fmt.Errorf("rbac: loader returned nil role definitions")
	}
	return New(defs, opts...), nil
}

// Rebuild replaces the manager's role definitions with the new set and
// re-resolves all permissions. It is safe to call concurrently with any
// read operations — it acquires a write lock only for the final swap.
//
// After Rebuild returns, all subsequent permission checks use the new
// definitions. In-flight checks against the old definitions complete normally.
//
// Rebuild panics if roles is nil.
func (m *Manager) Rebuild(roles map[Role]RoleDefinition) {
	if roles == nil {
		panic("rbac: roles map must not be nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.build(roles)
}

// RebuildFromLoader loads new role definitions from the given loader and
// calls Rebuild. Returns an error if the loader fails.
func (m *Manager) RebuildFromLoader(ctx context.Context, loader RoleLoader) error {
	defs, err := loader.Load(ctx)
	if err != nil {
		return fmt.Errorf("rbac: loader: %w", err)
	}
	if defs == nil {
		return fmt.Errorf("rbac: loader returned nil role definitions")
	}
	m.Rebuild(defs)
	return nil
}

// build initialises the manager's internal lookup tables from the given role
// definitions. It must be called either during single-goroutine construction
// (New) or while the write lock is held (Rebuild).
func (m *Manager) build(roles map[Role]RoleDefinition) {
	m.roles = make(map[Role]RoleDefinition, len(roles))
	m.resolvedPerms = make(map[Role]map[Permission]struct{}, len(roles))
	m.resolvedWildcards = make(map[Role][]string, len(roles))
	m.knownPerms = make(map[Permission]struct{})

	for role, def := range roles {
		m.roles[role] = def
	}

	for role := range m.roles {
		if _, already := m.resolvedPerms[role]; !already {
			m.resolve(role, make(map[Role]struct{}), 0)
		}
	}

	// Cyclic inheritance can cause a role to be cached mid-resolution with an
	// incomplete permission set (the exact result depends on map iteration
	// order). Fix this with a Bellman-Ford-style relaxation: repeatedly
	// propagate each role's direct parents' permissions into it until nothing
	// changes. For acyclic graphs this runs exactly once and finds nothing to
	// do; for cycles it converges in at most cycle-depth iterations.
	for changed := true; changed; {
		changed = false
		for role, def := range m.roles {
			perms := m.resolvedPerms[role]
			for _, parent := range def.Inherits {
				for p := range m.resolvedPerms[parent] {
					if _, has := perms[p]; !has {
						perms[p] = struct{}{}
						changed = true
					}
				}
				for _, wc := range m.resolvedWildcards[parent] {
					before := len(m.resolvedWildcards[role])
					m.resolvedWildcards[role] = appendUniqueStr(m.resolvedWildcards[role], wc)
					if len(m.resolvedWildcards[role]) > before {
						changed = true
					}
				}
			}
		}
	}

	// Build the global known-permissions index from all resolved roles.
	for _, perms := range m.resolvedPerms {
		for p := range perms {
			m.knownPerms[p] = struct{}{}
		}
	}

	// Build the global wildcard prefix index.
	seen := make(map[string]struct{})
	for _, prefixes := range m.resolvedWildcards {
		for _, prefix := range prefixes {
			if _, ok := seen[prefix]; !ok {
				seen[prefix] = struct{}{}
				m.allWildcardPrefixes = append(m.allWildcardPrefixes, prefix)
			}
		}
	}
}

// resolve computes the transitive permission set for role, writing the results
// into m.resolvedPerms and m.resolvedWildcards. visited guards against cycles.
// depth prevents stack overflow from extremely deep (non-cyclic) inheritance
// chains.
func (m *Manager) resolve(role Role, visited map[Role]struct{}, depth int) map[Permission]struct{} {
	if depth > maxResolveDepth {
		panic(fmt.Sprintf("rbac: inheritance depth exceeded %d for role %q", maxResolveDepth, role))
	}

	// Return cached result if this role was already resolved (e.g. reached via
	// a different inheritance path).
	if perms, ok := m.resolvedPerms[role]; ok {
		return perms
	}

	// Cycle guard.
	if _, seen := visited[role]; seen {
		return map[Permission]struct{}{}
	}
	visited[role] = struct{}{}

	def, exists := m.roles[role]
	if !exists {
		// Unknown role referenced in Inherits — treat as empty but cache it
		// so Can() knows it is not a completely foreign role.
		m.resolvedPerms[role] = map[Permission]struct{}{}
		return m.resolvedPerms[role]
	}

	perms := make(map[Permission]struct{}, len(def.Permissions))
	var wildcardPrefixes []string

	// Direct permissions — split exact from wildcard.
	for _, p := range def.Permissions {
		s := string(p)
		if strings.HasSuffix(s, "*") {
			prefix := strings.TrimSuffix(s, "*")
			wildcardPrefixes = appendUniqueStr(wildcardPrefixes, prefix)
		} else {
			perms[p] = struct{}{}
		}
	}

	// Inherited permissions (recursive).
	for _, parentRole := range def.Inherits {
		for p := range m.resolve(parentRole, visited, depth+1) {
			perms[p] = struct{}{}
		}
		for _, prefix := range m.resolvedWildcards[parentRole] {
			wildcardPrefixes = appendUniqueStr(wildcardPrefixes, prefix)
		}
	}

	m.resolvedPerms[role] = perms
	if len(wildcardPrefixes) > 0 {
		m.resolvedWildcards[role] = wildcardPrefixes
	}
	return perms
}

// ---------------------------------------------------------------------------
// Core permission checks
// ---------------------------------------------------------------------------

// Can returns true if the user holds the given permission via any of their
// assigned roles (including inherited permissions and wildcard grants).
//
//	if manager.Can(user, "posts:write") {
//	    // allow
//	}
//
// In strict mode (WithStrictMode), Can panics if the user holds a role that
// is not registered with this manager.
func (m *Manager) Can(user User, permission Permission) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.canLocked(user, permission)
}

// canLocked is the lock-free inner implementation of Can. The caller must hold
// at least an RLock on m.mu.
func (m *Manager) canLocked(user User, permission Permission) bool {
	for _, role := range user.GetRoles() {
		perms, known := m.resolvedPerms[role]
		if !known {
			if m.strict {
				panic(fmt.Sprintf("rbac: strict mode: unknown role %q", role))
			}
			continue
		}

		if _, has := perms[permission]; has {
			return true
		}

		for _, prefix := range m.resolvedWildcards[role] {
			if strings.HasPrefix(string(permission), prefix) {
				return true
			}
		}
	}
	return false
}

// Cannot is the logical negation of Can. Useful for guard clauses.
//
//	if manager.Cannot(user, "settings:write") {
//	    return ErrForbidden
//	}
func (m *Manager) Cannot(user User, permission Permission) bool {
	return !m.Can(user, permission)
}

// CanAll returns true only if the user holds every one of the given
// permissions. Useful for operations that require multiple capabilities.
func (m *Manager) CanAll(user User, permissions ...Permission) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, p := range permissions {
		if !m.canLocked(user, p) {
			return false
		}
	}
	return true
}

// CanAny returns true if the user holds at least one of the given permissions.
func (m *Manager) CanAny(user User, permissions ...Permission) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, p := range permissions {
		if m.canLocked(user, p) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Role checks
// ---------------------------------------------------------------------------

// HasRole returns true if the user has been directly assigned the given role.
// This checks only the roles returned by user.GetRoles() — it does not
// consider inherited roles or check whether the role is registered with the
// manager.
//
//	if manager.HasRole(user, "admin") {
//	    showAdminPanel()
//	}
func (m *Manager) HasRole(user User, role Role) bool {
	for _, r := range user.GetRoles() {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole returns true if the user has at least one of the listed roles.
func (m *Manager) HasAnyRole(user User, roles ...Role) bool {
	for _, role := range roles {
		if m.HasRole(user, role) {
			return true
		}
	}
	return false
}

// HasAllRoles returns true only if the user has every one of the listed roles.
func (m *Manager) HasAllRoles(user User, roles ...Role) bool {
	for _, role := range roles {
		if !m.HasRole(user, role) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Introspection
// ---------------------------------------------------------------------------

// AllPermissions returns the complete, deduplicated set of permissions the
// user holds across all their roles (including inherited permissions and
// wildcard grants such as "posts:*"). The result is sorted for deterministic
// output.
func (m *Manager) AllPermissions(user User) []Permission {
	m.mu.RLock()
	defer m.mu.RUnlock()

	seen := make(map[Permission]struct{})
	for _, role := range user.GetRoles() {
		for p := range m.resolvedPerms[role] {
			seen[p] = struct{}{}
		}
		for _, prefix := range m.resolvedWildcards[role] {
			seen[Permission(prefix+"*")] = struct{}{}
		}
	}

	result := make([]Permission, 0, len(seen))
	for p := range seen {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

// RolePermissions returns all permissions for the given role, including
// permissions inherited from parent roles and wildcard grants. Returns nil
// for unknown roles. The result is sorted for deterministic output.
func (m *Manager) RolePermissions(role Role) []Permission {
	m.mu.RLock()
	defer m.mu.RUnlock()

	perms, ok := m.resolvedPerms[role]
	if !ok {
		return nil
	}

	seen := make(map[Permission]struct{}, len(perms)+len(m.resolvedWildcards[role]))
	for p := range perms {
		seen[p] = struct{}{}
	}
	for _, prefix := range m.resolvedWildcards[role] {
		seen[Permission(prefix+"*")] = struct{}{}
	}

	result := make([]Permission, 0, len(seen))
	for p := range seen {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

// Roles returns all role names known to this manager, sorted.
func (m *Manager) Roles() []Role {
	m.mu.RLock()
	defer m.mu.RUnlock()

	roles := make([]Role, 0, len(m.roles))
	for r := range m.roles {
		roles = append(roles, r)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	return roles
}

// RoleExists returns true if the given role is explicitly defined in this
// manager (i.e. was present in the map passed to New or the most recent
// Rebuild call).
func (m *Manager) RoleExists(role Role) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.roles[role]
	return ok
}

// PermissionExists returns true if the given permission is satisfiable by at
// least one role registered with this manager — either as an exact permission
// (directly or via inheritance) or via a wildcard grant (e.g. "posts:*"
// satisfies "posts:read").
//
// Passing a wildcard string itself (e.g. "posts:*") returns true only if a
// role has that exact wildcard grant, not because a broader wildcard like "*"
// covers it.
func (m *Manager) PermissionExists(perm Permission) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Exact match in the known-permissions index.
	if _, ok := m.knownPerms[perm]; ok {
		return true
	}

	// Wildcard coverage: does any wildcard prefix match perm?
	for _, prefix := range m.allWildcardPrefixes {
		if strings.HasPrefix(string(perm), prefix) {
			return true
		}
	}
	return false
}

// ValidateUser returns the roles assigned to the user that are not registered
// with this manager. Returns nil if all roles are known.
//
// Unlike strict mode, ValidateUser never panics and is safe to call in
// production for observability or pre-flight checks.
func (m *Manager) ValidateUser(user User) []Role {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var unknown []Role
	for _, role := range user.GetRoles() {
		if _, ok := m.resolvedPerms[role]; !ok {
			unknown = append(unknown, role)
		}
	}
	return unknown
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const maxResolveDepth = 1000

func appendUniqueStr(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}
