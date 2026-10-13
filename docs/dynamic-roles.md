# Dynamic Roles (Database-Driven)

By design, `go-rbac` is agnostic about where role definitions come from. You own the data layer; the library owns the permission checks. This document shows how to wire up a database (or any external source) to drive roles and permissions at runtime.

## How the Manager works

`rbac.New()` accepts a plain `map[rbac.Role]rbac.RoleDefinition` and resolves all inheritance chains eagerly into an immutable snapshot. Permission checks read that snapshot without taking any lock.

This means:

- **At startup** — load from your DB with `rbac.NewFromLoader()`, inject the manager into your app.
- **On change** — call `manager.RebuildFromLoader()`; the manager resolves the new definitions and swaps its snapshot atomically.

## Minimal example — load from SQL

```go
package main

import (
    "context"
    "database/sql"

    _ "github.com/lib/pq"
    rbac "github.com/martinsuchenak/go-rbac"
)

// loadDefinitions queries the database and returns role definitions. Wrap it
// in rbac.RoleLoaderFunc to use with NewFromLoader / RebuildFromLoader.
func loadDefinitions(ctx context.Context, db *sql.DB) (map[rbac.Role]rbac.RoleDefinition, error) {
    // Expected schema:
    //
    //   roles(id, name, parent_role_name)
    //   permissions(id, name)
    //   role_permissions(role_id, permission_id)
    rows, err := db.QueryContext(ctx, `
        SELECT r.name, p.name, r.parent_role_name
        FROM roles r
        LEFT JOIN role_permissions rp ON r.id = rp.role_id
        LEFT JOIN permissions p       ON rp.permission_id = p.id
    `)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    defs := map[rbac.Role]rbac.RoleDefinition{}

    for rows.Next() {
        var roleName string
        var permName, parentName sql.NullString

        if err := rows.Scan(&roleName, &permName, &parentName); err != nil {
            return nil, err
        }

        role := rbac.Role(roleName)
        def := defs[role]

        if permName.Valid {
            def.Permissions = append(def.Permissions, rbac.Permission(permName.String))
        }
        if parentName.Valid {
            def.Inherits = appendUnique(def.Inherits, rbac.Role(parentName.String))
        }

        defs[role] = def
    }
    if err := rows.Err(); err != nil {
        return nil, err
    }

    return defs, nil
}

func appendUnique(roles []rbac.Role, r rbac.Role) []rbac.Role {
    for _, existing := range roles {
        if existing == r {
            return roles
        }
    }
    return append(roles, r)
}
```

## Hot-reload without downtime

When roles change (e.g. an admin creates a new role via your UI), call `RebuildFromLoader` on the existing manager. The manager swaps its resolved state atomically, so readers are never blocked and never see a half-built state, and you can keep handing the same `*rbac.Manager` to the rest of your code.

```go
loader := rbac.RoleLoaderFunc(func(ctx context.Context) (map[rbac.Role]rbac.RoleDefinition, error) {
    return loadDefinitions(ctx, db)
})

manager, err := rbac.NewFromLoader(ctx, loader)
// ...

func reloadRoles(ctx context.Context) error {
    // On error the previous definitions stay in effect.
    return manager.RebuildFromLoader(ctx, loader)
}
```

Rebuilds are serialized, and the loader call runs inside that critical section. Two reloads triggered close together (e.g. two admin edits) therefore cannot apply out of order: the one that loaded last is the one that stays in effect.

Trigger `reloadRoles` via:

- A background goroutine polling the DB for a `roles_updated_at` timestamp.
- A webhook or internal admin API endpoint.
- A pub/sub message when the roles table changes.

## Suggested DB schema

```sql
CREATE TABLE roles (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    parent_role_name TEXT REFERENCES roles(name)
);

CREATE TABLE permissions (
    id   SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE   -- e.g. "posts:write"
);

CREATE TABLE role_permissions (
    role_id       INT REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INT REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);
```

## Loading from a config file (YAML / JSON)

The same pattern applies to any structured source. Example with JSON:

```go
type roleConfig struct {
    Roles map[string]struct {
        Permissions []string `json:"permissions"`
        Inherits    []string `json:"inherits"`
    } `json:"roles"`
}

func loadManagerFromJSON(data []byte) (*rbac.Manager, error) {
    var cfg roleConfig
    if err := json.Unmarshal(data, &cfg); err != nil {
        return nil, err
    }

    defs := make(map[rbac.Role]rbac.RoleDefinition, len(cfg.Roles))
    for name, r := range cfg.Roles {
        def := rbac.RoleDefinition{}
        for _, p := range r.Permissions {
            def.Permissions = append(def.Permissions, rbac.Permission(p))
        }
        for _, i := range r.Inherits {
            def.Inherits = append(def.Inherits, rbac.Role(i))
        }
        defs[rbac.Role(name)] = def
    }

    return rbac.New(defs), nil
}
```

## Performance notes

- `rbac.New()` is O(roles × permissions) — runs once at startup or reload.
- `manager.Can()` is O(roles assigned to the user) with a hash-map lookup per role — effectively O(1).
- Permission checks are lock-free; `Rebuild` / `RebuildFromLoader` publish a new immutable snapshot with a single atomic store.
