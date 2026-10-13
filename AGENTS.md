# AGENTS.md — go-rbac

Codebase guide for AI agents and contributors.

## What this is

A Go RBAC library: pure permission evaluation engine with no external dependencies.
It evaluates whether a user (with assigned roles) holds a given permission.
It does **not** handle auth, session management, persistence, or change distribution.

## Module

```
github.com/martinsuchenak/go-rbac  (Go 1.26.3)
```

## File map

| Path | Purpose |
| ---- | ------- |
| `rbac.go` | Core engine: types, Manager, all check/introspection methods |
| `rbac_test.go` | Full test suite for the core package (external) |
| `rbac_internal_test.go` | Internal tests accessing unexported methods |
| `middleware/middleware.go` | `net/http` middleware wrappers over the Manager |
| `middleware/middleware_test.go` | Tests for the middleware package |
| `examples/basic/main.go` | Core API walkthrough (no HTTP) |
| `examples/inheritance/main.go` | Deep and diamond role inheritance demo |
| `examples/dynamic/main.go` | Wildcards, dynamic loading, hot-reload, strict mode, Guard |
| `examples/webserver/main.go` | Full HTTP server with middleware |
| `docs/dynamic-roles.md` | DB loading, hot-reload patterns, schema example |
| `Taskfile.yml` | Task runner: test, vet, lint, tidy, check |

## Architecture

### Manager lifecycle

```
rbac.New(defs, opts...)          ← constructs; calls build() once
rbac.NewFromLoader(ctx, loader)  ← loads defs then calls New

Manager.Rebuild(defs)            ← takes writeMu; build() then atomic store
Manager.RebuildFromLoader(...)   ← takes writeMu; loads defs, build(), atomic store
```

`build()` is the single point of initialization. It returns a new immutable `*snapshot` (it never touches the manager's current state) holding four lookup structures:

- `resolvedPerms map[Role]map[Permission]struct{}` — transitive exact permissions per role
- `resolvedWildcards map[Role][]string` — stripped wildcard prefixes (e.g. `"posts:"` for `"posts:*"`)
- `knownPerms map[Permission]struct{}` — union of all exact permissions across all roles
- `allWildcardPrefixes []string` — deduplicated union of all wildcard prefixes across all roles

Input `RoleDefinition` slices are cloned, and a snapshot is never mutated after `Manager.snap.Store`. A failed build leaves the previous snapshot in place.

### Wildcard resolution

Permissions ending in `"*"` are split off during `resolve()`. The `"*"` suffix is stripped and the remaining prefix is stored in `resolvedWildcards`. `Can()` first does an exact map lookup, then iterates the prefix list for the role. The empty prefix (from `"*"` alone) matches any permission string via `strings.HasPrefix`.

### resolve()

Recursive with a `visited map[Role]struct{}` guard and a depth counter that returns `ErrInheritanceTooDeep` above 1000. Called once per role during `build()`. Results are cached in `resolvedPerms` so each role is resolved at most once even with shared parents (diamond inheritance). Each role's chain height is recorded in `snapshot.heights` (build-time only) and checked on cache hits, so the depth limit does not depend on map iteration order.

### Concurrency model

- `New()` / `NewFromLoader()` — single goroutine, no lock needed.
- `Can()` and all read methods — one `snap.Load()`, then lock-free reads. Multi-check methods (`CanAll`, `CanAny`, `HasAnyRole`, `HasAllRoles`) load the snapshot once so they see one consistent set of definitions.
- `Rebuild()` / `RebuildFromLoader()` — hold `writeMu` for build + store (and the loader call), so writers are serialized and the last-started rebuild wins.
- A panic inside `Can()` (strict mode) is safe: no lock is held on the read path.

## Key design decisions

| Decision | Rationale |
| -------- | --------- |
| Eager resolution in `build()` | O(1) read path; no runtime traversal |
| Immutable snapshot behind `atomic.Pointer` | Lock-free reads; rebuilds never block or half-update readers |
| `writeMu` held across load + build | Concurrent reloads cannot apply out of order |
| `string` prefixes in `resolvedWildcards` | Avoids re-parsing `"posts:*"` on every `Can()` call |
| `knownPerms` index | O(1) `PermissionExists` exact lookup |
| `allWildcardPrefixes` index | O(prefixes) `PermissionExists` wildcard lookup without per-role iteration |
| `can(snapshot, roles, perm)` internal method | `CanAll`/`CanAny` evaluate against one snapshot and call `GetRoles` once |
| `ValidateUser` never panics | Safe for production; strict mode is dev/test only |
| Bad definitions → error, not panic | `Rebuild`, `NewFromLoader`, `RebuildFromLoader` return `ErrNilRoles` / `ErrInheritanceTooDeep`; only `New` (which cannot return an error) panics |
| Notifications/caching out of scope | The library evaluates permissions; orchestration belongs in the caller |

## Adding a new feature

1. If it changes the Manager struct, update `build()` to initialise the new field.
2. If it changes `resolve()` semantics, add a test for inheritance and cycle cases.
3. New public methods need godoc comments.
4. Run `task check` before committing.

## Testing conventions

- Tests live in `rbac_test.go` (external `rbac_test` package) and `middleware/middleware_test.go`.
- Use the `user(roles...)` helper to construct test users.
- Group tests by feature with `// ---` section dividers.
- Table-driven cases for variant coverage; individual `t.Run` subtests for named cases.
- Always include a concurrent-reads test when adding state to the snapshot.
- Strict-mode panic tests use `defer func() { recover() }()`.

## Running the test suite

```bash
task test          # go test -race -count=1 ./...
task check         # vet + lint + test
go test -run TestWildcard ./...   # run a specific group
```

## What NOT to add to this library

- Persistence, DB drivers, or query logic
- Redis, gossip, or any distributed coordination
- Auth middleware (JWT parsing, session lookup)
- Audit logging (wrap the Manager externally if needed)
- Role assignment (that belongs to the consuming application)
