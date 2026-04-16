package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	rbac "github.com/martinsuchenak/go-rbac"
	"github.com/martinsuchenak/go-rbac/middleware"
)

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

type testUser struct {
	roles []rbac.Role
}

func (u *testUser) GetRoles() []rbac.Role { return u.roles }

func newManager() *rbac.Manager {
	return rbac.New(map[rbac.Role]rbac.RoleDefinition{
		"viewer": {
			Permissions: []rbac.Permission{"posts:read"},
		},
		"editor": {
			Permissions: []rbac.Permission{"posts:read", "posts:write"},
		},
		"admin": {
			Permissions: []rbac.Permission{"users:read", "users:write"},
			Inherits:    []rbac.Role{"editor"},
		},
	})
}

// okHandler returns 200 OK with body "ok".
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
})

// extractorFor returns a UserExtractor that always yields the given user.
func extractorFor(u rbac.User) middleware.UserExtractor {
	return func(r *http.Request) (rbac.User, bool) {
		return u, true
	}
}

// noUserExtractor always signals that no user is present.
var noUserExtractor middleware.UserExtractor = func(r *http.Request) (rbac.User, bool) {
	return nil, false
}

func get() *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	return req
}

// ---------------------------------------------------------------------------
// Require (single permission)
// ---------------------------------------------------------------------------

func TestRequire_AllowsWhenPermitted(t *testing.T) {
	m := newManager()
	u := &testUser{roles: []rbac.Role{"editor"}}

	mw := middleware.Require(m, extractorFor(u), "posts:write")
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, get())

	if rec.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rec.Code)
	}
}

func TestRequire_ForbidsWhenLackingPermission(t *testing.T) {
	m := newManager()
	u := &testUser{roles: []rbac.Role{"viewer"}}

	mw := middleware.Require(m, extractorFor(u), "posts:write")
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, get())

	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

func TestRequire_ReturnsUnauthorizedWhenNoUser(t *testing.T) {
	m := newManager()
	mw := middleware.Require(m, noUserExtractor, "posts:read")
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, get())

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rec.Code)
	}
}

func TestRequire_CustomHandlers(t *testing.T) {
	m := newManager()
	u := &testUser{roles: []rbac.Role{"viewer"}}

	customForbidden := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	mw := middleware.Require(m, extractorFor(u), "posts:write", middleware.Options{
		OnForbidden: customForbidden,
	})
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, get())

	if rec.Code != http.StatusTeapot {
		t.Errorf("want 418, got %d", rec.Code)
	}
}

func TestRequire_InheritedPermission(t *testing.T) {
	m := newManager()
	// admin inherits editor → should have posts:write
	u := &testUser{roles: []rbac.Role{"admin"}}

	mw := middleware.Require(m, extractorFor(u), "posts:write")
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, get())

	if rec.Code != http.StatusOK {
		t.Errorf("want 200 (inherited permission), got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// RequireAll
// ---------------------------------------------------------------------------

func TestRequireAll_AllowsWhenAllPresent(t *testing.T) {
	m := newManager()
	u := &testUser{roles: []rbac.Role{"admin"}}

	mw := middleware.RequireAll(m, extractorFor(u), []rbac.Permission{"posts:read", "users:write"})
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, get())

	if rec.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rec.Code)
	}
}

func TestRequireAll_ForbidsWhenAnyMissing(t *testing.T) {
	m := newManager()
	u := &testUser{roles: []rbac.Role{"editor"}}

	mw := middleware.RequireAll(m, extractorFor(u), []rbac.Permission{"posts:write", "users:write"})
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, get())

	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// RequireAny
// ---------------------------------------------------------------------------

func TestRequireAny_AllowsWhenOnePresent(t *testing.T) {
	m := newManager()
	u := &testUser{roles: []rbac.Role{"viewer"}}

	mw := middleware.RequireAny(m, extractorFor(u), []rbac.Permission{"posts:read", "posts:write"})
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, get())

	if rec.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rec.Code)
	}
}

func TestRequireAny_ForbidsWhenNonePresent(t *testing.T) {
	m := newManager()
	u := &testUser{roles: []rbac.Role{"viewer"}}

	mw := middleware.RequireAny(m, extractorFor(u), []rbac.Permission{"users:read", "users:write"})
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, get())

	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// RequireRole
// ---------------------------------------------------------------------------

func TestRequireRole_AllowsWhenRoleAssigned(t *testing.T) {
	m := newManager()
	u := &testUser{roles: []rbac.Role{"admin"}}

	mw := middleware.RequireRole(m, extractorFor(u), "admin")
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, get())

	if rec.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rec.Code)
	}
}

func TestRequireRole_ForbidsWhenRoleMissing(t *testing.T) {
	m := newManager()
	u := &testUser{roles: []rbac.Role{"editor"}}

	mw := middleware.RequireRole(m, extractorFor(u), "admin")
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, get())

	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// RequireAnyRole
// ---------------------------------------------------------------------------

func TestRequireAnyRole_AllowsWhenOneRoleMatches(t *testing.T) {
	m := newManager()
	u := &testUser{roles: []rbac.Role{"editor"}}

	mw := middleware.RequireAnyRole(m, extractorFor(u), []rbac.Role{"admin", "editor"})
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, get())

	if rec.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rec.Code)
	}
}

func TestRequireAnyRole_ForbidsWhenNoMatch(t *testing.T) {
	m := newManager()
	u := &testUser{roles: []rbac.Role{"viewer"}}

	mw := middleware.RequireAnyRole(m, extractorFor(u), []rbac.Role{"admin", "editor"})
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, get())

	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// InjectUser / UserFromContext
// ---------------------------------------------------------------------------

func TestInjectUser_SetsContext(t *testing.T) {
	u := &testUser{roles: []rbac.Role{"admin"}}

	var capturedUser rbac.User
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser, _ = middleware.UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	mw := middleware.InjectUser(extractorFor(u))
	rec := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec, get())

	if capturedUser == nil {
		t.Fatal("expected user in context, got nil")
	}
	if capturedUser != u {
		t.Error("context user does not match injected user")
	}
}

func TestInjectUser_ContinuesWithoutUser(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := middleware.UserFromContext(r.Context())
		if ok {
			t.Error("expected no user in context for anonymous request")
		}
		w.WriteHeader(http.StatusOK)
	})

	mw := middleware.InjectUser(noUserExtractor)
	rec := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec, get())

	if rec.Code != http.StatusOK {
		t.Errorf("want 200 (anonymous allowed through InjectUser), got %d", rec.Code)
	}
}

func TestUserFromContext_EmptyContext(t *testing.T) {
	_, ok := middleware.UserFromContext(context.Background())
	if ok {
		t.Error("expected false for empty context")
	}
}

// ---------------------------------------------------------------------------
// Guard (inline check)
// ---------------------------------------------------------------------------

func TestGuard_AllowsWhenPermitted(t *testing.T) {
	m := newManager()
	u := &testUser{roles: []rbac.Role{"editor"}}

	rec := httptest.NewRecorder()
	allowed := middleware.Guard(rec, get(), m, u, "posts:write")
	if !allowed {
		t.Error("expected Guard to return true")
	}
	if rec.Code != http.StatusOK {
		// Guard should not have written anything when allowed.
		t.Errorf("Guard wrote status %d, expected no write (200 default)", rec.Code)
	}
}

func TestGuard_ForbidsWhenLackingPermission(t *testing.T) {
	m := newManager()
	u := &testUser{roles: []rbac.Role{"viewer"}}

	rec := httptest.NewRecorder()
	allowed := middleware.Guard(rec, get(), m, u, "posts:write")
	if allowed {
		t.Error("expected Guard to return false")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

func TestGuard_UnauthorizedWhenNoUser(t *testing.T) {
	m := newManager()

	rec := httptest.NewRecorder()
	allowed := middleware.Guard(rec, get(), m, nil, "posts:write")
	if allowed {
		t.Error("expected Guard to return false for nil user")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Middleware chaining
// ---------------------------------------------------------------------------

func TestChainedMiddleware(t *testing.T) {
	m := newManager()
	u := &testUser{roles: []rbac.Role{"editor"}}

	extractor := extractorFor(u)

	// InjectUser → Require: the common pattern for route protection.
	handler := middleware.InjectUser(extractor)(
		middleware.Require(m, extractor, "posts:write")(okHandler),
	)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, get())

	if rec.Code != http.StatusOK {
		t.Errorf("want 200, got %d", rec.Code)
	}
}
