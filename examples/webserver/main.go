// Package main demonstrates using the RBAC library with a net/http web server.
//
// It shows:
//   - Route-level permission guards via middleware.Require
//   - Role-level guards via middleware.RequireRole
//   - User injection into context so handlers don't re-run extraction logic
//   - Inline permission checks inside a handler via middleware.Guard
//   - A custom 403/401 handler to return JSON instead of plain text
//
// Run with: go run ./examples/webserver
// Then test with:
//
//	curl -H "X-User-Role: viewer"     http://localhost:8080/posts
//	curl -H "X-User-Role: editor"     http://localhost:8080/posts/create
//	curl -H "X-User-Role: admin"      http://localhost:8080/admin
//	curl                              http://localhost:8080/posts   # → 401
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	rbac "github.com/martinsuchenak/go-rbac"
	mw "github.com/martinsuchenak/go-rbac/middleware"
)

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

const (
	RoleViewer rbac.Role = "viewer"
	RoleEditor rbac.Role = "editor"
	RoleAdmin  rbac.Role = "admin"

	PermPostsRead  rbac.Permission = "posts:read"
	PermPostsWrite rbac.Permission = "posts:write"
	PermUsersRead  rbac.Permission = "users:read"
	PermUsersWrite rbac.Permission = "users:write"
)

// RequestUser represents the authenticated caller on a request.
type RequestUser struct {
	ID   int
	Name string
	role rbac.Role
}

func (u *RequestUser) GetRoles() []rbac.Role { return []rbac.Role{u.role} }

// ---------------------------------------------------------------------------
// Auth layer (simplified: reads role from a request header)
// ---------------------------------------------------------------------------

// extractUser is the UserExtractor provided to the middleware package.
// In a real application this would validate a JWT, look up a session, etc.
func extractUser(r *http.Request) (rbac.User, bool) {
	roleHeader := r.Header.Get("X-User-Role")
	if roleHeader == "" {
		return nil, false
	}
	return &RequestUser{
		ID:   42,
		Name: "Demo User",
		role: rbac.Role(roleHeader),
	}, true
}

// ---------------------------------------------------------------------------
// Custom error responses (JSON instead of plain text)
// ---------------------------------------------------------------------------

func jsonError(status int, msg string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
	}
}

var (
	unauthorizedHandler = jsonError(http.StatusUnauthorized, "authentication required")
	forbiddenHandler    = jsonError(http.StatusForbidden, "insufficient permissions")
)

var errorOpts = mw.Options{
	OnUnauthorized: unauthorizedHandler,
	OnForbidden:    forbiddenHandler,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func listPostsHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := mw.UserFromContext(r.Context())
	respond(w, map[string]any{
		"posts":        []string{"Hello World", "Go is great"},
		"requested_by": userName(user),
	})
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := mw.UserFromContext(r.Context())
	respond(w, map[string]any{
		"message":      "Post created successfully",
		"created_by":   userName(user),
	})
}

// adminHandler shows inline permission checking inside handler logic.
func adminHandler(mgr *rbac.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, _ := mw.UserFromContext(r.Context())

		// Inline guard: check an additional permission inside the handler.
		// This is useful when one handler serves multiple sub-operations.
		canWriteUsers := mgr.Can(user, PermUsersWrite)

		respond(w, map[string]any{
			"message":         "Admin panel",
			"admin":           userName(user),
			"can_write_users": canWriteUsers,
		})
	}
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	// This endpoint is unprotected; anyone (including anonymous) may reach it.
	user, ok := mw.UserFromContext(r.Context())
	if ok {
		respond(w, map[string]any{"authenticated": true, "user": userName(user)})
	} else {
		respond(w, map[string]any{"authenticated": false})
	}
}

// ---------------------------------------------------------------------------
// Server setup
// ---------------------------------------------------------------------------

func buildRouter(mgr *rbac.Manager) http.Handler {
	mux := http.NewServeMux()

	// Inject the user into context for all routes. Downstream middleware and
	// handlers can read the user from context via mw.UserFromContext.
	injectUser := mw.InjectUser(extractUser)

	// Public — no login required.
	mux.HandleFunc("/profile", profileHandler)

	// Requires posts:read permission.
	mux.Handle("/posts",
		injectUser(
			mw.Require(mgr, extractUser, PermPostsRead, errorOpts)(
				http.HandlerFunc(listPostsHandler),
			),
		),
	)

	// Requires posts:write permission.
	mux.Handle("/posts/create",
		injectUser(
			mw.Require(mgr, extractUser, PermPostsWrite, errorOpts)(
				http.HandlerFunc(createPostHandler),
			),
		),
	)

	// Requires the "admin" role directly.
	mux.Handle("/admin",
		injectUser(
			mw.RequireRole(mgr, extractUser, RoleAdmin, errorOpts)(
				adminHandler(mgr),
			),
		),
	)

	// Requires EITHER users:read OR users:write (at least one).
	mux.Handle("/users",
		injectUser(
			mw.RequireAny(mgr, extractUser, []rbac.Permission{PermUsersRead, PermUsersWrite}, errorOpts)(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					respond(w, map[string]any{"users": []string{"alice", "bob", "carol"}})
				}),
			),
		),
	)

	return mux
}

func main() {
	mgr := rbac.New(map[rbac.Role]rbac.RoleDefinition{
		RoleViewer: {
			Permissions: []rbac.Permission{PermPostsRead},
		},
		RoleEditor: {
			Permissions: []rbac.Permission{PermPostsRead, PermPostsWrite},
		},
		RoleAdmin: {
			Permissions: []rbac.Permission{PermUsersRead, PermUsersWrite},
			Inherits:    []rbac.Role{RoleEditor},
		},
	})

	router := buildRouter(mgr)

	addr := ":8080"
	fmt.Printf("Listening on %s\n\n", addr)
	fmt.Println("Try these requests:")
	fmt.Println("  curl -H 'X-User-Role: viewer'  http://localhost:8080/posts")
	fmt.Println("  curl -H 'X-User-Role: editor'  http://localhost:8080/posts/create")
	fmt.Println("  curl -H 'X-User-Role: admin'   http://localhost:8080/admin")
	fmt.Println("  curl -H 'X-User-Role: viewer'  http://localhost:8080/admin  # → 403")
	fmt.Println("  curl                            http://localhost:8080/posts  # → 401")
	fmt.Println("  curl                            http://localhost:8080/profile # → ok (public)")

	log.Fatal(http.ListenAndServe(addr, router))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func respond(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func userName(u any) string {
	if ru, ok := u.(*RequestUser); ok {
		return ru.Name
	}
	return "anonymous"
}
