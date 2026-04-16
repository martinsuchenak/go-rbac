# go-rbac

[![Go Reference](https://pkg.go.dev/badge/github.com/martinsuchenak/go-rbac.svg)](https://pkg.go.dev/github.com/martinsuchenak/go-rbac)

A lightweight Role-Based Access Control (RBAC) engine for Go.

- Zero dependencies — standard library only
- Roles and permissions are plain strings; no schema imposed
- Wildcard grants: `"posts:*"` covers `"posts:read"`, `"posts:write"`, etc.
- Deep role inheritance with cycle detection
- O(1) permission checks via eager resolution at startup
- Hot-reload via `Rebuild` / `RebuildFromLoader` (concurrent-safe)
- `net/http`-compatible middleware included

## Installation

```bash
go get github.com/martinsuchenak/go-rbac
```

## Quick Start

```go
import rbac "github.com/martinsuchenak/go-rbac"

manager := rbac.New(map[rbac.Role]rbac.RoleDefinition{
    "viewer": {Permissions: []rbac.Permission{"posts:read"}},
    "editor": {Permissions: []rbac.Permission{"posts:read", "posts:write"}},
    "admin": {
        Permissions: []rbac.Permission{"users:read", "users:write"},
        Inherits:    []rbac.Role{"editor"},
    },
})

manager.Can(user, "posts:write")               // true/false
manager.CanAll(user, "posts:read", "users:read") // must hold all
manager.CanAny(user, "posts:write", "users:read") // at least one
manager.Cannot(user, "settings:write")           // negation guard
```

Implement `rbac.User` on your existing user struct:

```go
func (u *AppUser) GetRoles() []rbac.Role { return u.Roles }
```

## API Reference

### Permission checks

| Method | Description |
| ------ | ----------- |
| `Can(user, perm)` | User holds this permission (exact or wildcard) |
| `Cannot(user, perm)` | Negation of `Can` |
| `CanAll(user, perms...)` | User holds every listed permission |
| `CanAny(user, perms...)` | User holds at least one listed permission |

### Role checks

| Method | Description |
| ------ | ----------- |
| `HasRole(user, role)` | Direct assignment only — not inherited |
| `HasAnyRole(user, roles...)` | At least one role matches |
| `HasAllRoles(user, roles...)` | All roles present |

### Introspection

| Method | Description |
| ------ | ----------- |
| `Roles()` | All defined role names, sorted |
| `RolePermissions(role)` | All permissions for a role including inherited and wildcards |
| `AllPermissions(user)` | All permissions across all of the user's roles |
| `RoleExists(role)` | Whether a role is registered |
| `PermissionExists(perm)` | Whether any role can satisfy this permission |
| `ValidateUser(user)` | Returns any roles the user holds that are unknown to the manager |

## Wildcard Permissions

A permission ending in `*` is a prefix grant:

```go
"posts:*"  // grants posts:read, posts:write, posts:delete, …
"*"        // grants everything
```

Wildcards inherit transitively and appear in `RolePermissions` / `AllPermissions` output.

## Role Inheritance

Inheritance is transitive and resolves at startup. Cycles and diamond patterns are handled safely.

```go
"admin": {
    Permissions: []rbac.Permission{"users:write"},
    Inherits:    []rbac.Role{"editor"},  // gets all editor permissions too
},
```

## Dynamic Roles

Load definitions from a database or any source, then call `rbac.New`:

```go
manager, err := rbac.NewFromLoader(ctx, rbac.RoleLoaderFunc(func(ctx context.Context) (map[rbac.Role]rbac.RoleDefinition, error) {
    return loadFromDB(ctx, db)
}))
```

For hot-reload when roles change at runtime:

```go
if err := manager.RebuildFromLoader(ctx, loader); err != nil {
    // handle — manager is unchanged on error
}
```

`Rebuild` and `RebuildFromLoader` are safe to call concurrently with reads. See [docs/dynamic-roles.md](docs/dynamic-roles.md) for a full DB schema and loading example.

## HTTP Middleware

```go
import mw "github.com/martinsuchenak/go-rbac/middleware"

extractor := func(r *http.Request) (rbac.User, bool) { /* read from JWT/session */ }

mux.Handle("/posts",  mw.Require(mgr, extractor, "posts:read")(handler))
mux.Handle("/admin",  mw.RequireRole(mgr, extractor, "admin")(handler))
mux.Handle("/",       mw.InjectUser(extractor)(router))   // user available via mw.UserFromContext
```

Custom error responses, `RequireAll`, `RequireAny`, `RequireAnyRole`, `RequireAllRoles`, and inline `Guard` are also available — see [godoc](https://pkg.go.dev/github.com/martinsuchenak/go-rbac/middleware).

## Development Options

`WithStrictMode()` causes `Can` to panic when the user holds an unregistered role. Useful in tests:

```go
manager := rbac.New(defs, rbac.WithStrictMode())
```

## Examples

| Example | Description |
| ------- | ----------- |
| [examples/basic](examples/basic/main.go) | Core API walkthrough |
| [examples/inheritance](examples/inheritance/main.go) | Deep and diamond inheritance |
| [examples/webserver](examples/webserver/main.go) | HTTP server with middleware |

```bash
go run ./examples/basic
go run ./examples/webserver
```

## Development

```bash
task test    # go test -race ./...
task vet     # go vet ./...
task lint    # golangci-lint
task tidy    # go mod tidy
task check   # vet + lint + test
```

## License

MIT
