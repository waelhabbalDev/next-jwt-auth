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
*   **Secure Cookie Storage:** Tokens are stored in `HttpOnly`, `Secure`, and `SameSite=Strict` cookies to protect against XSS and CSRF.
*   **Next.js 14+ Ready:** Built for the App Router. Works seamlessly with Server Components, Server Actions, API Route Handlers, and Middleware.
*   **Type-Safe Client Hooks:** Generic React Hooks (`useAuth`) for simple, type-safe client-side session management powered by SWR.
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
    forbidden: "/unauthorized", // Optional: fallback to unauthenticated if not set
  },
});
```

### 3. Set Up Middleware

The middleware handles automatic token refreshing.

```ts
// middleware.ts
import { auth } from "@/lib/auth";

export default auth.createAuthMiddleware();

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
```

### 4. Set up the Client-Side Provider

Create a session API endpoint and wrap your application in the `AuthProvider`.

```ts
// app/api/auth/session/route.ts
import { auth } from "@/lib/auth";
import { NextResponse } from "next/server";

export async function GET() {
  const session = await auth.getAuthSession();
  return NextResponse.json(session);
}
```

```tsx
// app/providers.tsx
"use client";
import { AuthProvider } from "@waelhabbalDev/next-jwt-auth/client";
import { signInAction, signOutAction } from "@/app/actions/authActions";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider
      sessionFetcher={() => fetch("/api/auth/session").then((res) => res.json())}
      signInAction={signInAction}
      signOutAction={signOutAction}
    >
      {children}
    </AuthProvider>
  );
}
```

Wrap your `RootLayout`'s children with `<Providers>`.

---

## Protecting Your Application

This library provides declarative guards to easily protect your application at every level.

### Protecting Pages (Server Components)

Use `auth.protectPage()` at the beginning of any page or layout. It guarantees that the user is authenticated, or it redirects them.

```tsx
// app/dashboard/page.tsx
import { auth } from "@/lib/auth";

export default async function DashboardPage() {
  // If the user is not logged in, they will be redirected to "/signin".
  // The session object is guaranteed to be available.
  const session = await auth.protectPage();

  return <h1>Welcome, {session.identity.fullName}</h1>;
}
```

You can also enforce roles and other authorization rules.

```tsx
// app/admin/page.tsx
import { auth } from "@/lib/auth";

export default async function AdminPage() {
  const session = await auth.protectPage({
    // If the user is not an admin, they will be redirected to "/unauthorized".
    authorize: (identity) => identity.roles.includes("admin"),
    redirectParams: { error: "admin_required" } // Adds ?error=... to the URL
  });

  return <h2>Admin Panel</h2>;
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
    // Throws NotAuthenticatedError if not logged in.
    const session = await auth.protectAction();

    // ... your logic here, e.g., create post in DB for session.identity.identifier
    
    return { success: true };
  } catch (error) {
    if (error instanceof NotAuthenticatedError) {
      return { success: false, error: "Please sign in to create a post." };
    }
    // Handle other errors...
    return { success: false, error: "An unknown error occurred." };
  }
}
```

### Protecting API Routes

Use `auth.protectApi()` to secure your Route Handlers. It returns a `NextResponse` on failure.

```ts
// app/api/projects/route.ts
import { auth } from "@/lib/auth";
import { NextResponse } from "next/server";

export async function GET() {
  const { session, response } = await auth.protectApi({
    authorize: (identity) => identity.roles.includes("project-manager"),
  });

  // If the guard fails, `response` will be a NextResponse object. Return it.
  if (response) {
    return response;
  }

  // If we reach here, the user is authenticated and authorized.
  const projects = await db.projects.findByUser(session.identity.identifier);
  return NextResponse.json(projects);
}
```

### Accessing the Session on the Client

Use the `useAuth()` hook in any Client Component.

```tsx
"use client";
import { useAuth } from "@waelhabbalDev/next-jwt-auth/client";
import { AppUserIdentity } from "@/lib/auth.types";

function ProfileButton() {
  const { identity, isLoading, signOut } = useAuth<AppUserIdentity>();

  if (isLoading) return <div>Loading...</div>;
  if (!identity) return <a href="/signin">Sign In</a>;

  return (
    <div>
      <span>Hello, {identity.fullName}</span>
      <button onClick={signOut}>Logout</button>
    </div>
  );
}
```

---

## API Reference

The `createAuth` function returns an object with the following methods:

| Method                 | Description                                                                                             |
| ---------------------- | ------------------------------------------------------------------------------------------------------- |
| `protectPage()`        | **(Recommended)** Protects Pages/Layouts. Redirects on failure.                                         |
| `protectAction()`      | **(Recommended)** Protects Server Actions. Throws a catchable error on failure.                         |
| `protectApi()`         | **(Recommended)** Protects API Routes. Returns a `NextResponse` with a 401/403 status on failure.       |
| `getAuthSession()`     | Fetches the current session without protection. Returns `null` if not authenticated.                    |
| `signIn()`             | Signs in a user and sets cookies. Called from a Server Action.                                          |
| `signOut()`            | Signs out a user, clears cookies, and invalidates the token family.                                     |
| `createAuthMiddleware()` | Creates Next.js middleware for automatic token refreshing.                                              |

---

## Security

*   **Refresh Token Rotation & Reuse Detection:** Provides state-of-the-art protection against token theft. If a stolen refresh token is used, all sessions for that user are immediately invalidated.
*   **Secure Cookies:** All tokens are stored in `HttpOnly`, `Secure`, and `SameSite=Strict` cookies to protect against XSS and CSRF attacks.
*   **Declarative Guards:** The `protectPage` and `protectAction` guards help prevent common security mistakes by ensuring authentication and authorization checks are always performed.

---

## Recommended Environment Variables

```env
# A secure, random string of at least 32 characters
ACCESS_TOKEN_SECRET="your-32+char-secret"
REFRESH_TOKEN_SECRET="your-32+char-secret"

# The full base URL of your application
BASE_URL="http://localhost:3000"
# For Vercel, this can be set automatically:
# BASE_URL="https://your-domain.com"

NODE_ENV="production"
```

---

## Keywords

`nextjs`, `authentication`, `authorization`, `jwt`, `auth`, `security`, `session-management`, `access-token`, `refresh-token`, `middleware`, `react-hooks`, `token-rotation`, `nextjs-auth`, `app-router`

---

## License

MIT License