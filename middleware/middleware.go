// Package middleware provides net/http-compatible RBAC middleware built on top
// of the github.com/martinsuchenak/go-rbac core engine.
//
// Because it uses only standard http.Handler / http.HandlerFunc interfaces, it
// is compatible with any router or framework that supports net/http middleware,
// including chi, gorilla/mux, and the standard library's own ServeMux.
//
// # Basic Usage
//
//	// 1. Create the RBAC manager (typically at application startup).
//	manager := rbac.New(...)
//
//	// 2. Define how to pull your User out of a request.
//	//    This is usually reading from a context value set by your auth layer.
//	extractor := func(r *http.Request) (rbac.User, bool) {
//	    user, ok := auth.UserFromContext(r.Context())
//	    return user, ok
//	}
//
//	// 3. Guard a route.
//	mux.Handle("/posts", middleware.Require(manager, extractor, "posts:read")(postsHandler))
//
//	// 4. Optionally inject the user into context so handlers can read it.
//	mux.Handle("/", middleware.InjectUser(extractor)(router))
package middleware

import (
	"context"
	"net/http"

	rbac "github.com/martinsuchenak/go-rbac"
)

// contextKey is an unexported type to prevent collisions with other packages
// that also store values in a request context.
type contextKey int

const userKey contextKey = iota

// UserExtractor is a function provided by the consuming application that
// retrieves the authenticated rbac.User from a request. Return false as the
// second value when no authenticated user is present (e.g. anonymous request).
type UserExtractor func(r *http.Request) (rbac.User, bool)

// Options customises the behaviour of RBAC middleware. All fields are optional;
// sensible HTTP defaults are used when nil.
type Options struct {
	// OnUnauthorized is called when the UserExtractor returns false.
	// Default: 401 Unauthorized plain-text response.
	OnUnauthorized http.HandlerFunc

	// OnForbidden is called when the user is authenticated but lacks the
	// required permission or role.
	// Default: 403 Forbidden plain-text response.
	OnForbidden http.HandlerFunc
}

func (o Options) unauthorized() http.HandlerFunc {
	if o.OnUnauthorized != nil {
		return o.OnUnauthorized
	}
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func (o Options) forbidden() http.HandlerFunc {
	if o.OnForbidden != nil {
		return o.OnForbidden
	}
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}

// ---------------------------------------------------------------------------
// Permission-based middleware
// ---------------------------------------------------------------------------

// Require returns middleware that allows the request to proceed only when the
// authenticated user holds the given permission. It calls the extractor to
// obtain the user from the request, then delegates the check to manager.Can.
//
//	mux.Handle("/api/posts", middleware.Require(mgr, extract, "posts:read")(handler))
func Require(manager *rbac.Manager, extractor UserExtractor, permission rbac.Permission, opt Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := extractor(r)
			if !ok {
				opt.unauthorized()(w, r)
				return
			}
			if !manager.Can(user, permission) {
				opt.forbidden()(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAll returns middleware that allows the request only when the user
// holds every one of the listed permissions.
func RequireAll(manager *rbac.Manager, extractor UserExtractor, permissions []rbac.Permission, opt Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := extractor(r)
			if !ok {
				opt.unauthorized()(w, r)
				return
			}
			if !manager.CanAll(user, permissions...) {
				opt.forbidden()(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAny returns middleware that allows the request when the user holds at
// least one of the listed permissions.
func RequireAny(manager *rbac.Manager, extractor UserExtractor, permissions []rbac.Permission, opt Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := extractor(r)
			if !ok {
				opt.unauthorized()(w, r)
				return
			}
			if !manager.CanAny(user, permissions...) {
				opt.forbidden()(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------------------
// Role-based middleware
// ---------------------------------------------------------------------------

// RequireRole returns middleware that allows the request only when the user
// holds the given role (direct assignment, not inheritance).
//
//	mux.Handle("/admin", middleware.RequireRole(mgr, extract, "admin")(adminHandler))
func RequireRole(manager *rbac.Manager, extractor UserExtractor, role rbac.Role, opt Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := extractor(r)
			if !ok {
				opt.unauthorized()(w, r)
				return
			}
			if !manager.HasRole(user, role) {
				opt.forbidden()(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole returns middleware that allows the request when the user has
// at least one of the listed roles.
func RequireAnyRole(manager *rbac.Manager, extractor UserExtractor, roles []rbac.Role, opt Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := extractor(r)
			if !ok {
				opt.unauthorized()(w, r)
				return
			}
			if !manager.HasAnyRole(user, roles...) {
				opt.forbidden()(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllRoles returns middleware that allows the request only when the
// user has been directly assigned every one of the listed roles.
func RequireAllRoles(manager *rbac.Manager, extractor UserExtractor, roles []rbac.Role, opt Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := extractor(r)
			if !ok {
				opt.unauthorized()(w, r)
				return
			}
			if !manager.HasAllRoles(user, roles...) {
				opt.forbidden()(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------------------
// User injection middleware
// ---------------------------------------------------------------------------

// InjectUser returns middleware that runs the extractor and, if it succeeds,
// stores the user in the request context. Downstream handlers and middleware
// can then retrieve it with UserFromContext rather than calling the extractor
// again.
//
// If the extractor returns false (anonymous request), InjectUser still calls
// the next handler — it does not reject unauthenticated requests. Combine with
// a Require* middleware for that.
func InjectUser(extractor UserExtractor) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if user, ok := extractor(r); ok {
				ctx := context.WithValue(r.Context(), userKey, user)
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// UserFromContext retrieves the rbac.User injected by InjectUser from the
// request context. The second return value is false when no user is present.
func UserFromContext(ctx context.Context) (rbac.User, bool) {
	u, ok := ctx.Value(userKey).(rbac.User)
	return u, ok
}

// ---------------------------------------------------------------------------
// Inline guard — useful inside handlers rather than on the route itself
// ---------------------------------------------------------------------------

// Guard is a helper for performing RBAC checks inside handler code rather than
// at the routing layer. It writes the appropriate error response and returns
// false when the check fails, so the caller can return early:
//
//	func myHandler(w http.ResponseWriter, r *http.Request) {
//	    user, _ := middleware.UserFromContext(r.Context())
//	    if !middleware.Guard(w, r, manager, user, "posts:write") {
//	        return
//	    }
//	    // ... proceed with the request
//	}
//
// Custom error responses can be provided via Options, consistent with the
// Require* middleware functions.
func Guard(w http.ResponseWriter, r *http.Request, manager *rbac.Manager, user rbac.User, permission rbac.Permission, opt Options) bool {
	if user == nil {
		opt.unauthorized()(w, r)
		return false
	}
	if !manager.Can(user, permission) {
		opt.forbidden()(w, r)
		return false
	}
	return true
}
