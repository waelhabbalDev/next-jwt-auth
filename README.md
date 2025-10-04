# @waelhabbalDev/next-jwt-auth

[![NPM Version](https://img.shields.io/npm/v/@waelhabbaldev/next-jwt-auth.svg)](https://www.npmjs.com/package/@waelhabbaldev/next-jwt-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<div align="center">
  <img src="icons/icon.svg" alt="Next.js JWT Auth" width="256" height="256">
</div>

<h3 align="center">Declarative, Secure Authentication for Next.js 14+</h3>

A lightweight, secure, and performance-optimized authentication library for the Next.js App Router. It implements a robust security model using JWT access/refresh tokens and provides a simple, declarative API to protect your pages, server actions, and API routes.

---

## Features

*   **State-of-the-Art Security:** Automatic Refresh Token Rotation and Reuse Detection to protect against token theft and session hijacking.
*   **Declarative Protection Guards:** Secure your application with a single line of code. Use `protectPage()`, `protectAction()`, and `protectApi()` to enforce authentication and authorization rules effortlessly.
*   **Optimized Performance:** The auth middleware provides built-in request-level caching, automatically preventing redundant database checks between Middleware and Server Components, which eliminates race conditions and ensures optimal performance.
*   **Flexible Authorization:** Implement role-based (RBAC) or ownership-based (ABAC) access control with a simple `authorize` callback in the protection guards.
*   **Granular Failure States:** Correctly distinguish between **Unauthenticated** (not logged in), **Forbidden** (account banned), and **Unauthorized** (lacks permissions), redirecting users or returning appropriate errors for each case.
*   **Secure Cookie Storage:** Tokens are stored in `HttpOnly`, `Secure`, and `SameSite=Strict` cookies to protect against XSS and CSRF.
*   **Next.js 14+ Ready:** Built for the App Router. Works seamlessly with Server Components, Server Actions, API Route Handlers, and Middleware.
*   **DAL Agnostic:** Plug in your own database logic (Prisma, Drizzle, etc.) via a simple `UserIdentityDAL` interface.
*   **Session Versioning:** Instantly invalidate all of a user's sessions from the server-side (e.g., after a password change).

---

## Installation

```bash
bun add @waelhabbaldev/next-jwt-auth
# or
npm install @waelhabbaldev/next-jwt-auth
# or
yarn add @waelhabbaldev/next-jwt-auth
```

---

## Database Schema Requirements

Your database needs two tables to support all security features.

#### 1. `users` Table
Must include `version` (for session invalidation) and `isForbidden` (for banning).

```sql
CREATE TABLE `users` (
  -- ... other user columns (userId, email, passwordHash, etc.)
  `version` INT UNSIGNED NOT NULL DEFAULT 1,
  `isForbidden` BOOLEAN NOT NULL DEFAULT FALSE
);
```

#### 2. `revokedTokens` Table
Required for refresh token reuse detection.

```sql
CREATE TABLE `revokedTokens` (
    `jti` VARCHAR(36) NOT NULL COMMENT 'The JWT ID, typically a UUID.',
    `expiresAt` TIMESTAMP NOT NULL COMMENT 'When the token can be safely deleted.',
    PRIMARY KEY (`jti`),
    INDEX `IX_revokedTokens_expiresAt` (`expiresAt`)
);
```
**Note:** You should run a scheduled job (e.g., a cron job) to periodically delete expired JTIs from this table to keep it clean: `DELETE FROM revokedTokens WHERE expiresAt < NOW();`.

---

## Quick Start

### 1. Define your User Identity and DAL

Define a type for your user's identity and implement the `UserIdentityDAL` interface to connect the library to your database.

```ts
// src/lib/auth-dal.ts
import type { UserIdentity, UserIdentityDAL } from "@waelhabbaldev/next-jwt-auth";
import db from "./db"; // Your database client (e.g., Prisma, Drizzle)

// Extend the base UserIdentity with your application's specific fields
export interface AppUserIdentity extends UserIdentity {
  userId: number;
  username: string;
  // You can add any other public user properties here
}

export const authDal: UserIdentityDAL<AppUserIdentity> = {
  // Verifies credentials and returns the full user identity on success.
  async fetchIdentityByCredentials(username, password) { /* ... */ },

  // Fetches the latest user identity during session refresh.
  async fetchIdentityForSession(identifier) { /* ... */ },

  // Bumps the user's `version`, invalidating all their sessions.
  async invalidateAllSessionsForIdentity(identifier) { /* ... */ },

  // Checks if a refresh token's JTI has been used.
  async isTokenJtiUsed(jti) { /* ... */ },

  // Stores a used JTI until its natural expiry to detect reuse.
  async markTokenJtiAsUsed(jti, expirationInSeconds) { /* ... */ },
};
```

### 2. Configure and Export the Auth Instance

Create a central file (`src/lib/auth.ts`) to configure and export your `auth` object. This is the single source of truth for your authentication system.

```ts
// src/lib/auth.ts
import { createAuth } from "@waelhabbaldev/next-jwt-auth";
import { authDal, AppUserIdentity } from "./auth-dal";

export const auth = createAuth<AppUserIdentity>({
  dal: authDal,
  
  // Your application's fully-qualified base URL
  baseUrl: process.env.BASE_URL!, 
  
  secrets: {
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET!,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  },
  
  cookies: {
    access: { name: "__at", maxAge: 15 * 60 },        // 15 minutes
    refresh: { name: "__rt", maxAge: 30 * 24 * 60 * 60 }, // 30 days
  },

  // Paths to redirect users to on authentication/authorization failure
  redirects: {
    unauthenticated: "/signin",
    unauthorized: "/dashboard?error=unauthorized", // User is logged in but lacks permissions
    forbidden: "/signin?error=forbidden",         // User's account is suspended/banned
  },
});
```

### 3. Set Up Middleware for Session Management

The middleware is the **most important part** of the setup. It handles automatic session refreshing and is the key to the library's performance and stability.

Create a `middleware.ts` file in the root of your project (or in `src/`).

```ts
// middleware.ts
import { auth } from "./lib/auth";

// The `createMiddleware` function from your auth instance will handle
// all session validation and token refreshing automatically.
export default auth.createMiddleware();

export const config = {
  // The middleware will run on all paths except for the ones specified here.
  // This is the recommended approach to ensure your session is always fresh.
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
```
> **How it works:** This middleware runs the full authentication check on every request. If the session is valid, it attaches the user's identity to a request header. This allows subsequent calls to `getSession()` or `protectPage()` within the same request to be **near-instantaneous, cached reads**, preventing database waterfalls and race conditions.

---

## Protecting Your Application

This library provides declarative guards to easily protect your application at every level.

### Protecting Pages and Layouts (Server Components)

Use `auth.protectPage()` to secure any Server Component. It will automatically redirect unauthenticated users.

```tsx
// app/dashboard/layout.tsx
import { auth } from "@/lib/auth";
import { AppUserIdentity } from "@/lib/auth-dal";
import { Sidebar } from "./_components/sidebar";

export default async function DashboardLayout({ children }) {
  // This call validates the session. Because of the middleware cache,
  // this is a fast, in-memory check if the user is already navigating the site.
  // It only hits the database on the first load or after the access token expires.
  const session = await auth.protectPage();
  const identity = session.identity as AppUserIdentity;

  return (
    <div className="flex">
      <Sidebar user={identity} />
      <main>{children}</main>
    </div>
  );
}
```

#### Role-Based Authorization (RBAC)
For pages requiring specific permissions, use the `authorize` option.

```tsx
// app/admin/page.tsx
import { auth } from "@/lib/auth";

export default async function AdminPage() {
  // If the logged-in user is not an admin, they will be redirected
  // to the `unauthorized` path defined in your config.
  const session = await auth.protectPage({
    authorize: (identity) => identity.roles.includes("admin"),
  });

  return <h2>Admin Panel</h2>;
}
```

#### Ownership-Based Authorization (ABAC)
Pass a `context` object to the guard for complex authorization checks.
```tsx
// app/posts/[id]/edit/page.tsx
import { auth } from "@/lib/auth";
import { getPostById } from "@/lib/data";

export default async function EditPostPage({ params }) {
  const post = await getPostById(params.id);

  const session = await auth.protectPage({
    // Check if the authenticated user's ID matches the post's author ID.
    authorize: (identity, postToCheck) => identity.identifier === postToCheck.authorId,
    context: post, // Pass the post object into the authorize function
  });

  // If we reach here, the user is authenticated AND is the owner.
  return <EditForm post={post} />;
}
```

### Protecting Server Actions

Use `auth.protectAction()` to secure your Server Actions. It throws specific, catchable errors on failure.

```ts
// app/actions/postActions.ts
"use server";
import { auth } from "@/lib/auth";
import { NotAuthenticatedError, ForbiddenError } from "@waelhabbaldev/next-jwt-auth";

export async function createPostAction(formData: FormData) {
  try {
    const session = await auth.protectAction({
        authorize: (identity) => identity.roles.includes('editor')
    });
    
    // ... logic for creating a post using session.identity ...
    return { success: true };
  } catch (error) {
    if (error instanceof NotAuthenticatedError) {
      return { success: false, error: "Please sign in to create a post." };
    }
    if (error instanceof ForbiddenError) {
      return { success: false, error: "You do not have permission to create posts." };
    }
    return { success: false, error: "An unknown error occurred." };
  }
}
```

### Protecting API Routes

Use `auth.protectApi()` to secure your Route Handlers. On failure, it returns a `response` object that you must return.

```ts
// app/api/projects/[id]/route.ts
import { auth } from "@/lib/auth";
import { NextResponse } from "next/server";

export async function GET(req, { params }) {
  const { session, response } = await auth.protectApi();

  // If the guard fails, `response` will be a NextResponse object. Return it.
  if (response) {
    return response;
  }

  // If we reach here, the user is authenticated.
  // TypeScript knows `session` is not null here.
  const project = await db.projects.findById(params.id, session.identity.identifier);
  return NextResponse.json(project);
}
```

---

## API Reference

The `createAuth` function returns an object with the following methods:

| Method             | Description                                                                                             | Failure Behavior |
| ------------------ | ------------------------------------------------------------------------------------------------------- | ---------------- |
| `protectPage()`    | Secures Pages/Layouts with optional authorization rules.                                                | Redirects        |
| `protectAction()`  | Secures Server Actions.                                                                                 | Throws Error     |
| `protectApi()`     | Secures API Routes.                                                                                     | Returns Response |
| `getSession()`     | **(Fast)** Fetches the session without protection. Reads from the middleware cache if available.          | Returns `null`   |
| `signIn()`         | Signs in a user and sets session cookies.                                                               | Throws Error     |
| `signOut()`        | Signs out a user and invalidates their session family.                                                  | (N/A)            |
| `createMiddleware()`| **(Essential)** Creates middleware for automatic token refreshing and request caching.                   | Redirects        |

---

## Keywords

`nextjs`, `authentication`, `authorization`, `jwt`, `auth`, `security`, `rbac`, `abac`, `session-management`, `access-token`, `refresh-token`, `middleware`, `react-hooks`, `token-rotation`, `nextjs-auth`, `app-router`

---

## License

MIT License