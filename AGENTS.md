# AGENTS.md — go-rbac

Codebase guide for AI agents and contributors.

## What this is

A Go RBAC library: pure permission evaluation engine with no external dependencies.
It evaluates whether a user (with assigned roles) holds a given permission.
It does **not** handle auth, session management, persistence, or change distribution.

## Module

```
github.com/martinsuchenak/go-rbac  (Go 1.26.2)
```

## File map

| Path | Purpose |
| ---- | ------- |
| `rbac.go` | Core engine: types, Manager, all check/introspection methods |
| `rbac_test.go` | Full test suite for the core package |
| `middleware/middleware.go` | `net/http` middleware wrappers over the Manager |
| `middleware/middleware_test.go` | Tests for the middleware package |
| `examples/basic/main.go` | Core API walkthrough (no HTTP) |
| `examples/inheritance/main.go` | Deep and diamond role inheritance demo |
| `examples/webserver/main.go` | Full HTTP server with middleware |
| `docs/dynamic-roles.md` | DB loading, hot-reload patterns, schema example |
| `Taskfile.yml` | Task runner: test, vet, lint, tidy, check |

## Architecture

### Manager lifecycle

```
rbac.New(defs, opts...)          ← constructs; calls build() once
rbac.NewFromLoader(ctx, loader)  ← loads defs then calls New

Manager.Rebuild(defs)            ← acquires write lock; calls build()
Manager.RebuildFromLoader(...)   ← loads defs then calls Rebuild
```

`build()` is the single point of initialization. It populates three maps:

- `resolvedPerms map[Role]map[Permission]struct{}` — transitive exact permissions per role
- `resolvedWildcards map[Role][]string` — stripped wildcard prefixes (e.g. `"posts:"` for `"posts:*"`)
- `knownPerms map[Permission]struct{}` — union of all exact permissions across all roles

After construction the maps are never mutated. Reads hold `sync.RWMutex` as an RLock; `Rebuild` holds it as a write lock during the swap.

### Wildcard resolution

Permissions ending in `"*"` are split off during `resolve()`. The `"*"` suffix is stripped and the remaining prefix is stored in `resolvedWildcards`. `Can()` first does an exact map lookup, then iterates the prefix list for the role. The empty prefix (from `"*"` alone) matches any permission string via `strings.HasPrefix`.

### resolve()

Recursive with a `visited map[Role]struct{}` guard. Called once per role during `build()`. Results are cached in `resolvedPerms` so each role is resolved at most once even with shared parents (diamond inheritance).

### Concurrency model

- `New()` — single goroutine, no lock needed.
- `Can()` and all read methods — `mu.RLock()` / `mu.RUnlock()`.
- `Rebuild()` — `mu.Lock()` / `mu.Unlock()` before calling `build()`.
- A panic inside `Can()` (strict mode) is safe: `defer mu.RUnlock()` fires before the panic propagates.

## Key design decisions

| Decision | Rationale |
| -------- | --------- |
| Eager resolution in `build()` | O(1) read path; no runtime traversal |
| Immutable maps after construction | Zero read-path lock contention |
| `string` prefixes in `resolvedWildcards` | Avoids re-parsing `"posts:*"` on every `Can()` call |
| `knownPerms` index | O(1) `PermissionExists` exact lookup |
| `ValidateUser` never panics | Safe for production; strict mode is dev/test only |
| Loader returns nil → error not panic | `NewFromLoader` / `RebuildFromLoader` are fallible; panic is reserved for programmer errors |
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
- Always include a concurrent-reads test when adding state that is read under RLock.
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
