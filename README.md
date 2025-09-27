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
Must include `tokenVersion` (for session invalidation) and `isForbidden` (for banning).

```sql
CREATE TABLE `users` (
  -- ... other user columns (userId, email, hashedPassword, etc.)
  `tokenVersion` INT NOT NULL DEFAULT 0,
  `isForbidden` BOOLEAN NOT NULL DEFAULT FALSE
);
```

#### 2. `usedRefreshToken` Table
Required for refresh token reuse detection.

```sql
CREATE TABLE `usedRefreshToken` (
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
// src/lib/auth.types.ts
import type { UserIdentity } from "@waelhabbalDev/next-jwt-auth";

export interface AppUserIdentity extends UserIdentity {
  fullName: string | null;
  email: string;
  // You can add any other public user properties here
}
```

```ts
// src/lib/dal.ts
import { UserIdentityDAL } from "@waelhabbalDev/next-jwt-auth";
import { AppUserIdentity } from "./auth.types";
import db from "./db"; // Your database client (e.g., Prisma)

export const dal: UserIdentityDAL<AppUserIdentity> = {
  // Implement all 5 DAL methods here...
  // fetchIdentityByCredentials, fetchIdentityForSession, etc.
};
```

### 2. Configure and Export the Auth Instance

Create a central file (`src/lib/auth.ts`) to configure and export your `auth` object. This is the single source of truth for your authentication system.

```ts
// src/lib/auth.ts
import { createAuth } from "@waelhabbalDev/next-jwt-auth";
import { dal } from "./dal";
import { AppUserIdentity } from "./auth.types";

export const auth = createAuth<AppUserIdentity>({
  dal,
  // Your application's fully-qualified base URL
  baseUrl: process.env.BASE_URL!, 
  
  secrets: {
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET!,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  },
  
  cookies: {
    access: { name: "auth-access-token", maxAge: 15 * 60 },       // 15 minutes
    refresh: { name: "auth-refresh-token", maxAge: 7 * 24 * 60 * 60 }, // 7 days
  },

  // Paths to redirect users to on authentication/authorization failure
  redirects: {
    unauthenticated: "/signin",
    unauthorized: "/unauthorized", // User is logged in but lacks permissions
    forbidden: "/forbidden",       // User's account is suspended/banned
  },
});
```

### 3. Set Up Middleware & Client Provider

The setup for middleware and the client-side `AuthProvider` remains straightforward. Refer to the package's `examples` directory for the full implementation.

---

## Protecting Your Application

This library provides declarative guards to easily protect your application at every level.

### Protecting Pages (Server Components)

Use `auth.protectPage()` at the beginning of any page or layout. It guarantees that the user is authenticated and authorized, or it redirects them to the correct page.

#### Basic Authentication
```tsx
// app/dashboard/page.tsx
import { auth } from "@/lib/auth";

export default async function DashboardPage() {
  // If not logged in, redirects to "/signin".
  // If the account is banned, redirects to "/forbidden".
  const session = await auth.protectPage();

  return <h1>Welcome, {session.identity.fullName}</h1>;
}
```

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
| `protectPage()`        | **(Recommended)** Secures Pages/Layouts.                                                                | Redirects        |
| `protectAction()`      | **(Recommended)** Secures Server Actions.                                                               | Throws Error     |
| `protectApi()`         | **(Recommended)** Secures API Routes.                                                                   | Returns Response |
| `getAuthSession()`     | Fetches the session without protection. Returns `null` if not authenticated.                            | Returns `null`   |
| `signIn()`             | Signs in a user and sets cookies.                                                                       | Throws Error     |
| `signOut()`            | Signs out a user and invalidates the token family.                                                      | (N/A)            |
| `createAuthMiddleware()` | Creates middleware for automatic token refreshing.                                                      | (N/A)            |

---

## Keywords

`nextjs`, `authentication`, `authorization`, `jwt`, `auth`, `security`, `rbac`, `abac`, `session-management`, `access-token`, `refresh-token`, `middleware`, `react-hooks`, `token-rotation`, `nextjs-auth`, `app-router`

---

## License

MIT License