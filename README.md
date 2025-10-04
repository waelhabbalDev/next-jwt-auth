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

*   **State-of-the-Art Security:** Automatic Refresh Token Rotation and Reuse Detection to protect against token theft.
*   **Declarative Protection Guards:** Secure your application with a single line of code. Use `auth.protectPage()`, `auth.protectAction()`, and `auth.protectApi()` to enforce authentication and authorization rules effortlessly.
*   **Optimized Performance:** Built-in request-level caching automatically prevents redundant authentication checks, eliminating race conditions between Middleware and Server Components and ensuring optimal performance.
*   **Flexible Authorization:** Implement role-based (RBAC) or ownership-based (ABAC) access control with a simple `authorize` callback in the protection guards.
*   **Granular Failure States:** Correctly distinguish between **Unauthenticated** (not logged in), **Forbidden** (account banned), and **Unauthorized** (lacks permissions) states, redirecting users to the appropriate page for each case.
*   **Secure Cookie Storage:** Tokens are stored in `HttpOnly`, `Secure`, and `SameSite=Strict` cookies to protect against XSS and CSRF.
*   **Next.js 14+ Ready:** Built for the App Router. Works seamlessly with Server Components, Server Actions, API Route Handlers, and Middleware.
*   **DAL Agnostic:** Plug in your own database logic (Prisma, Drizzle, etc.) via a simple `UserIdentityDAL` interface.
*   **Session Versioning:** Instantly invalidate all of a user's sessions from the server-side (e.g., after a password change).

---

## Installation

```bash
bun add @waelhabbalDev/next-jwt-auth
# or
npm install @waelhabbalDev/next-jwt-auth
# or
yarn add @waelhabbalDev/next-jwt-auth
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
<!-- START MODIFICATION -->
_**Note:** The column name `tokenVersion` has been updated to `version` in the latest examples for brevity._
<!-- END MODIFICATION -->

#### 2. `revokedTokens` Table
Required for refresh token reuse detection.

```sql
CREATE TABLE `revokedTokens` (
    `jti` VARCHAR(36) NOT NULL,
    `expiresAt` TIMESTAMP NOT NULL,
    PRIMARY KEY (`jti`)
);
```
**Note:** You should run a scheduled job (e.g., a cron job) to periodically delete expired JTIs from this table to keep it clean.

---

## Quick Start

### 1. Define your User Identity and DAL

Define a type for your user's identity and implement the `UserIdentityDAL` interface to connect the library to your database.

```ts
// src/lib/auth-dal.ts
import type { UserIdentity, UserIdentityDAL } from "@waelhabbalDev/next-jwt-auth";
import db from "./db"; // Your database client (e.g., Prisma)

export interface AppUserIdentity extends UserIdentity {
  userId: number;
  username: string;
  // You can add any other public user properties here
}

export const authDal: UserIdentityDAL<AppUserIdentity> = {
  // Implement all 5 DAL methods here...
  // fetchIdentityByCredentials, fetchIdentityForSession, etc.
};
```

### 2. Configure and Export the Auth Instance

Create a central file (`src/lib/auth.ts`) to configure and export your `auth` object. This is the single source of truth for your authentication system.

```ts
// src/lib/auth.ts
import { createAuth } from "@waelhabbalDev/next-jwt-auth";
import { authDal } from "./auth-dal";
import { AppUserIdentity } from "./auth-dal";

export const auth = createAuth<AppUserIdentity>({
  dal: authDal,
  // Your application's fully-qualified base URL
  baseUrl: process.env.BASE_URL!, 
  
  secrets: {
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET!,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  },
  
  cookies: {
    access: { name: "____at", maxAge: 15 * 60 },       // 15 minutes
    refresh: { name: "____rt", maxAge: 7 * 24 * 60 * 60 }, // 7 days
  },

  // Paths to redirect users to on authentication/authorization failure
  redirects: {
    unauthenticated: "/signin",
    unauthorized: "/unauthorized", // User is logged in but lacks permissions
    forbidden: "/forbidden",       // User's account is suspended/banned
  },
});
```

<!-- START MODIFICATION -->
### 3. Set Up Middleware for Session Management

The middleware is the most important part of the setup. It handles automatic session refreshing and is the key to the library's performance and stability.

Create a `middleware.ts` file in the root of your project (or in `src/`).

```ts
// middleware.ts
import { NextRequest } from "next/server";
import { auth } from "./lib/auth";

// The `createAuthMiddleware` function from your auth instance will handle
// all session validation, token refreshing, and redirects for unauthenticated
// users on the routes you specify.
const authMiddleware = auth.createAuthMiddleware(
  // This matcher function determines which routes are protected.
  (req: NextRequest) => {
    const { pathname } = req.nextUrl;
    // Return `true` for any path that requires authentication.
    return pathname.startsWith("/dashboard");
  }
);

export default authMiddleware;

export const config = {
  // Match all paths except for static assets and API routes.
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
```
> **How it works:** This middleware runs the full authentication check. If the session is valid, it attaches the user's identity to a request header. This allows subsequent calls to `auth.getAuthSession()` or `auth.protectPage()` within the same request to be near-instantaneous, preventing database waterfalls and race conditions.
<!-- END MODIFICATION -->

---

## Protecting Your Application

This library provides declarative guards to easily protect your application at every level.

<!-- START MODIFICATION -->
### Protecting Pages and Layouts (Server Components)

For protected areas of your app (like a dashboard), it's best practice to protect the root layout. Use `auth.getAuthSession()` to read the session that was already validated by the middleware.

```tsx
// app/dashboard/layout.tsx
import { auth } from "@/lib/auth";
import { redirect } from "next/navigation";

export default async function DashboardLayout({ children }) {
  // The middleware has already validated the session and refreshed tokens if needed.
  // This call is a fast, cached read that doesn't re-validate with the database.
  const session = await auth.getAuthSession();

  // This check acts as a server-side safety net.
  if (!session) {
    redirect("/signin");
  }

  return <div>Welcome, {session.identity.username}</div>;
}
```

For pages requiring specific permissions (e.g., role-based access), use `auth.protectPage()`.

#### Role-Based Authorization (RBAC)
```tsx
// app/admin/page.tsx
import { auth } from "@/lib/auth";

export default async function AdminPage() {
  const session = await auth.protectPage({
    // If the logged-in user is not an admin, they will be redirected to "/unauthorized".
    authorize: (identity) => identity.roles.includes("admin"),
  });

  return <h2>Admin Panel</h2>;
}
```
<!-- END MODIFICATION -->

#### Ownership-Based Authorization (ABAC)
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
    
    // ... logic for creating a post ...
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

Use `auth.protectApi()` to secure your Route Handlers. It returns a `NextResponse` on failure.

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
  const project = await db.projects.findById(params.id, session.identity.identifier);
  return NextResponse.json(project);
}
```

---

## API Reference

The `createAuth` function returns an object with the following methods:

| Method                 | Description                                                                                             | Failure Behavior |
| ---------------------- | ------------------------------------------------------------------------------------------------------- | ---------------- |
| `protectPage()`        | Secures Pages/Layouts with fine-grained authorization rules.                                            | Redirects        |
| `protectAction()`      | Secures Server Actions.                                                                                 | Throws Error     |
| `protectApi()`         | Secures API Routes.                                                                                     | Returns Response |
| `getAuthSession()`     | **(Fast)** Fetches the session without protection. Reads from a request-level cache.                      | Returns `null`   |
| `signIn()`             | Signs in a user and sets cookies.                                                                       | Throws Error     |
| `signOut()`            | Signs out a user and invalidates the token family.                                                      | (N/A)            |
| `createAuthMiddleware()` | **(Essential)** Creates middleware for automatic token refreshing and request caching.                   | Redirects        |

---

## Keywords

`nextjs`, `authentication`, `authorization`, `jwt`, `auth`, `security`, `rbac`, `abac`, `session-management`, `access-token`, `refresh-token`, `middleware`, `react-hooks`, `token-rotation`, `nextjs-auth`, `app-router`

---

## License

MIT License