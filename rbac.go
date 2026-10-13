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
// Matching is a plain string prefix test and is not aware of any separator:
// "posts*" (no colon) also grants "postscript:read". Include the separator in
// the grant ("posts:*") to scope it to a single segment.
//
// Wildcards are inherited transitively and appear verbatim in AllPermissions
// and RolePermissions output. When definitions come from untrusted or
// user-editable data, WithoutWildcards makes every permission match exactly.
//
// # Dynamic and database-driven roles
//
// Implement RoleLoader (or use RoleLoaderFunc) to load definitions from any
// external source:
//
//	manager, err := rbac.NewFromLoader(ctx, rbac.RoleLoaderFunc(loadFromDB))
//
// To update a live manager without downtime, call Rebuild or RebuildFromLoader.
// Both are safe to call concurrently with ongoing permission checks, which are
// lock-free and never observe a partially built state. Concurrent rebuilds are
// serialized, so the definitions applied last always win.
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
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// Roles is a list of roles that satisfies User. Use it when the caller already
// has the role names at hand and no richer user type is needed:
//
//	manager.Can(rbac.Roles{"editor", "billing"}, "posts:write")
type Roles []Role

// GetRoles implements User.
func (r Roles) GetRoles() []Role { return r }

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
// Errors
// ---------------------------------------------------------------------------

// ErrNilRoles is returned by Rebuild and the loader functions when the role
// definitions map is nil.
var ErrNilRoles = errors.New("rbac: roles map must not be nil")

// ErrInheritanceTooDeep is returned when a role's (non-cyclic) inheritance
// chain is longer than the supported maximum depth.
var ErrInheritanceTooDeep = errors.New("rbac: inheritance depth exceeded")

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
	return func(m *Manager) { m.strict = true }
}

// WithoutWildcards returns an Option that disables wildcard grants: a
// permission ending in "*" is then an ordinary permission that only matches a
// check for that exact string. Use it when role definitions come from data
// that should not be able to grant broad access by accident.
func WithoutWildcards() Option {
	return func(m *Manager) { m.noWildcards = true }
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

// Manager is the RBAC engine. Create one with New or NewFromLoader, then use
// its methods to perform access checks throughout your application.
//
// Manager is safe for concurrent use. Read operations are lock-free: each one
// works against an immutable snapshot of the resolved definitions. Rebuild and
// RebuildFromLoader build a complete new snapshot without blocking readers and
// then publish it atomically.
type Manager struct {
	// snap is the current resolved state. It is replaced wholesale on
	// Rebuild and never mutated after being published.
	snap atomic.Pointer[snapshot]

	// writeMu serializes rebuilds (including the loader call in
	// RebuildFromLoader) so the most recently started rebuild is the one
	// whose definitions stay in effect.
	writeMu sync.Mutex

	strict      bool
	noWildcards bool
}

// snapshot is the immutable, fully resolved form of a set of role
// definitions.
type snapshot struct {
	roles map[Role]RoleDefinition

	// resolvedPerms holds the transitive exact-permission sets for each role.
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

	// heights holds, per resolved role, the length of its longest inheritance
	// chain. Only used during build so the depth limit applies the same way
	// regardless of the order roles are resolved in; nil once published.
	heights map[Role]int
}

// New constructs a Manager from the provided role definitions and optional
// configuration options. It resolves role inheritance eagerly so that runtime
// permission checks are O(roles assigned to the user) with a cheap map lookup
// per role.
//
// New panics if roles is nil or an inheritance chain exceeds the maximum
// depth. Use NewFromLoader to get these as errors instead.
//
//	rbac.New(defs)
//	rbac.New(defs, rbac.WithStrictMode())
func New(roles map[Role]RoleDefinition, opts ...Option) *Manager {
	m, err := newManager(roles, opts)
	if err != nil {
		panic(err.Error())
	}
	return m
}

// NewFromLoader constructs a Manager by loading role definitions from the
// provided loader. It returns an error if the loader fails, returns a nil map,
// or the definitions cannot be resolved.
func NewFromLoader(ctx context.Context, loader RoleLoader, opts ...Option) (*Manager, error) {
	defs, err := loader.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: loader: %w", err)
	}
	return newManager(defs, opts)
}

func newManager(roles map[Role]RoleDefinition, opts []Option) (*Manager, error) {
	m := &Manager{}
	for _, opt := range opts {
		opt(m)
	}
	s, err := m.build(roles)
	if err != nil {
		return nil, err
	}
	m.snap.Store(s)
	return m, nil
}

// Rebuild replaces the manager's role definitions with the new set. The new
// definitions are fully resolved before being published, so concurrent
// permission checks see either the old or the new definitions, never a mix,
// and are not blocked while the rebuild runs.
//
// Rebuild returns ErrNilRoles if roles is nil and ErrInheritanceTooDeep if an
// inheritance chain is too long. On error the previous definitions remain in
// effect.
func (m *Manager) Rebuild(roles map[Role]RoleDefinition) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	return m.rebuildLocked(roles)
}

// RebuildFromLoader loads new role definitions from the given loader and
// applies them as Rebuild does. The load and the swap happen under the same
// lock as Rebuild, so when rebuilds race the definitions loaded last are the
// ones that stay in effect. On error the previous definitions remain in
// effect.
func (m *Manager) RebuildFromLoader(ctx context.Context, loader RoleLoader) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	defs, err := loader.Load(ctx)
	if err != nil {
		return fmt.Errorf("rbac: loader: %w", err)
	}
	return m.rebuildLocked(defs)
}

func (m *Manager) rebuildLocked(roles map[Role]RoleDefinition) error {
	s, err := m.build(roles)
	if err != nil {
		return err
	}
	m.snap.Store(s)
	return nil
}

// build resolves the given role definitions into a new snapshot. It does not
// touch the manager's current state.
func (m *Manager) build(roles map[Role]RoleDefinition) (*snapshot, error) {
	if roles == nil {
		return nil, ErrNilRoles
	}

	s := &snapshot{
		roles:             make(map[Role]RoleDefinition, len(roles)),
		resolvedPerms:     make(map[Role]map[Permission]struct{}, len(roles)),
		resolvedWildcards: make(map[Role][]string, len(roles)),
		knownPerms:        make(map[Permission]struct{}),
		heights:           make(map[Role]int, len(roles)),
	}

	// Copy the definitions, including their slices, so later changes by the
	// caller cannot leak into the published snapshot.
	for role, def := range roles {
		s.roles[role] = RoleDefinition{
			Permissions: slices.Clone(def.Permissions),
			Inherits:    slices.Clone(def.Inherits),
		}
	}

	for role := range s.roles {
		if _, already := s.resolvedPerms[role]; !already {
			if _, err := s.resolve(role, make(map[Role]struct{}), 0, !m.noWildcards); err != nil {
				return nil, err
			}
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
		for role, def := range s.roles {
			perms := s.resolvedPerms[role]
			for _, parent := range def.Inherits {
				for p := range s.resolvedPerms[parent] {
					if _, has := perms[p]; !has {
						perms[p] = struct{}{}
						changed = true
					}
				}
				for _, wc := range s.resolvedWildcards[parent] {
					before := len(s.resolvedWildcards[role])
					s.resolvedWildcards[role] = appendUniqueStr(s.resolvedWildcards[role], wc)
					if len(s.resolvedWildcards[role]) > before {
						changed = true
					}
				}
			}
		}
	}

	// Build the global known-permissions index from all resolved roles.
	for _, perms := range s.resolvedPerms {
		maps.Copy(s.knownPerms, perms)
	}

	// Build the global wildcard prefix index.
	seen := make(map[string]struct{})
	for _, prefixes := range s.resolvedWildcards {
		for _, prefix := range prefixes {
			if _, ok := seen[prefix]; !ok {
				seen[prefix] = struct{}{}
				s.allWildcardPrefixes = append(s.allWildcardPrefixes, prefix)
			}
		}
	}

	s.heights = nil
	return s, nil
}

// resolve computes the transitive permission set for role, writing the results
// into s.resolvedPerms and s.resolvedWildcards. visited guards against cycles.
// depth bounds extremely deep (non-cyclic) inheritance chains so they fail
// with ErrInheritanceTooDeep instead of overflowing the stack.
func (s *snapshot) resolve(role Role, visited map[Role]struct{}, depth int, wildcards bool) (map[Permission]struct{}, error) {
	if depth > maxResolveDepth {
		return nil, fmt.Errorf("%w: more than %d levels at role %q", ErrInheritanceTooDeep, maxResolveDepth, role)
	}

	// Return cached result if this role was already resolved (e.g. reached via
	// a different inheritance path). The cached chain still counts towards the
	// depth limit, otherwise the limit would depend on resolution order.
	if perms, ok := s.resolvedPerms[role]; ok {
		if depth+s.heights[role] > maxResolveDepth {
			return nil, fmt.Errorf("%w: more than %d levels at role %q", ErrInheritanceTooDeep, maxResolveDepth, role)
		}
		return perms, nil
	}

	// Cycle guard.
	if _, seen := visited[role]; seen {
		return map[Permission]struct{}{}, nil
	}
	visited[role] = struct{}{}

	def, exists := s.roles[role]
	if !exists {
		// Unknown role referenced in Inherits — treat as empty but cache it
		// so Can() knows it is not a completely foreign role.
		s.resolvedPerms[role] = map[Permission]struct{}{}
		return s.resolvedPerms[role], nil
	}

	perms := make(map[Permission]struct{}, len(def.Permissions))
	var wildcardPrefixes []string

	// Direct permissions — split exact from wildcard.
	for _, p := range def.Permissions {
		if prefix, ok := strings.CutSuffix(string(p), "*"); ok && wildcards {
			wildcardPrefixes = appendUniqueStr(wildcardPrefixes, prefix)
		} else {
			perms[p] = struct{}{}
		}
	}

	// Inherited permissions (recursive).
	height := 0
	for _, parentRole := range def.Inherits {
		parentPerms, err := s.resolve(parentRole, visited, depth+1, wildcards)
		if err != nil {
			return nil, err
		}
		height = max(height, s.heights[parentRole]+1)
		maps.Copy(perms, parentPerms)
		for _, prefix := range s.resolvedWildcards[parentRole] {
			wildcardPrefixes = appendUniqueStr(wildcardPrefixes, prefix)
		}
	}

	s.resolvedPerms[role] = perms
	s.heights[role] = height
	if len(wildcardPrefixes) > 0 {
		s.resolvedWildcards[role] = wildcardPrefixes
	}
	return perms, nil
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
	return m.can(m.snap.Load(), user.GetRoles(), permission)
}

// can checks permission against a single snapshot so that multi-permission
// checks (CanAll, CanAny) see one consistent set of definitions.
func (m *Manager) can(s *snapshot, roles []Role, permission Permission) bool {
	for _, role := range roles {
		if _, registered := s.roles[role]; !registered {
			if m.strict {
				panic(fmt.Sprintf("rbac: strict mode: unknown role %q", role))
			}
			continue
		}

		if _, has := s.resolvedPerms[role][permission]; has {
			return true
		}

		for _, prefix := range s.resolvedWildcards[role] {
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
	s, roles := m.snap.Load(), user.GetRoles()
	for _, p := range permissions {
		if !m.can(s, roles, p) {
			return false
		}
	}
	return true
}

// CanAny returns true if the user holds at least one of the given permissions.
func (m *Manager) CanAny(user User, permissions ...Permission) bool {
	s, roles := m.snap.Load(), user.GetRoles()
	for _, p := range permissions {
		if m.can(s, roles, p) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Role checks
// ---------------------------------------------------------------------------

// HasRole returns true if the user has been directly assigned the given role
// and that role is registered with this manager. It does not consider inherited
// roles — only the exact roles returned by user.GetRoles(). If the role is not
// registered with this manager, HasRole returns false even if the user carries
// that role string.
//
//	if manager.HasRole(user, "admin") {
//	    showAdminPanel()
//	}
func (m *Manager) HasRole(user User, role Role) bool {
	return hasRole(m.snap.Load(), user.GetRoles(), role)
}

func hasRole(s *snapshot, roles []Role, role Role) bool {
	if _, registered := s.roles[role]; !registered {
		return false
	}
	return slices.Contains(roles, role)
}

// HasAnyRole returns true if the user has at least one of the listed roles.
func (m *Manager) HasAnyRole(user User, roles ...Role) bool {
	s, assigned := m.snap.Load(), user.GetRoles()
	for _, role := range roles {
		if hasRole(s, assigned, role) {
			return true
		}
	}
	return false
}

// HasAllRoles returns true only if the user has every one of the listed roles.
func (m *Manager) HasAllRoles(user User, roles ...Role) bool {
	s, assigned := m.snap.Load(), user.GetRoles()
	for _, role := range roles {
		if !hasRole(s, assigned, role) {
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
	s := m.snap.Load()

	seen := make(map[Permission]struct{})
	for _, role := range user.GetRoles() {
		maps.Copy(seen, s.resolvedPerms[role])
		for _, prefix := range s.resolvedWildcards[role] {
			seen[Permission(prefix+"*")] = struct{}{}
		}
	}

	return slices.Sorted(maps.Keys(seen))
}

// RolePermissions returns all permissions for the given role, including
// permissions inherited from parent roles and wildcard grants. Returns nil
// for unknown roles. The result is sorted for deterministic output.
func (m *Manager) RolePermissions(role Role) []Permission {
	s := m.snap.Load()

	perms, ok := s.resolvedPerms[role]
	if !ok {
		return nil
	}

	seen := make(map[Permission]struct{}, len(perms)+len(s.resolvedWildcards[role]))
	maps.Copy(seen, perms)
	for _, prefix := range s.resolvedWildcards[role] {
		seen[Permission(prefix+"*")] = struct{}{}
	}

	return slices.Sorted(maps.Keys(seen))
}

// RoleHasPermission returns true if the given role has the specified permission,
// either directly or through inheritance (including wildcard grants). Returns
// false for unknown roles. This is an O(1) alternative to constructing a fake
// user and calling Can().
func (m *Manager) RoleHasPermission(role Role, permission Permission) bool {
	s := m.snap.Load()

	perms, ok := s.resolvedPerms[role]
	if !ok {
		return false
	}

	if _, has := perms[permission]; has {
		return true
	}

	for _, prefix := range s.resolvedWildcards[role] {
		if strings.HasPrefix(string(permission), prefix) {
			return true
		}
	}
	return false
}

// Roles returns all role names known to this manager, sorted.
func (m *Manager) Roles() []Role {
	return slices.Sorted(maps.Keys(m.snap.Load().roles))
}

// RoleExists returns true if the given role is explicitly defined in this
// manager (i.e. was present in the map passed to New or the most recent
// Rebuild call).
func (m *Manager) RoleExists(role Role) bool {
	_, ok := m.snap.Load().roles[role]
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
	s := m.snap.Load()

	// Exact match in the known-permissions index.
	if _, ok := s.knownPerms[perm]; ok {
		return true
	}

	// Wildcard coverage: does any wildcard prefix match perm?
	for _, prefix := range s.allWildcardPrefixes {
		if strings.HasPrefix(string(perm), prefix) {
			return true
		}
	}
	return false
}

// ValidateUser returns the roles assigned to the user that are not explicitly
// defined in this manager. Returns nil if all roles are known. A role is
// considered "known" only if it was present in the map passed to New or the
// most recent Rebuild call — roles that exist solely as inherited references
// (i.e. appear in another role's Inherits but have no own definition) are
// treated as unknown.
//
// Unlike strict mode, ValidateUser never panics and is safe to call in
// production for observability or pre-flight checks.
func (m *Manager) ValidateUser(user User) []Role {
	s := m.snap.Load()

	var unknown []Role
	for _, role := range user.GetRoles() {
		if _, ok := s.roles[role]; !ok {
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
	if slices.Contains(slice, s) {
		return slice
	}
	return append(slice, s)
}
