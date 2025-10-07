# @waelhabbalDev/next-jwt-auth

[![NPM Version](https://img.shields.io/npm/v/@waelhabbaldev/next-jwt-auth.svg)](https://www.npmjs.com/package/@waelhabbaldev/next-jwt-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<div align="center">
  <img src="icons/icon.svg" alt="Next.js JWT Auth" width="256" height="256">
</div>

<h3 align="center">Declarative, Secure, Enterprise-Grade Authentication for Next.js</h3>

A lightweight, secure, and performance-optimized authentication library for the Next.js App Router. It implements a robust, multi-layered security model using JWTs and provides a simple, declarative API to protect your pages, server actions, and API routes.

---

## Features

*   **State-of-the-Art Security:** Automatic Refresh Token Rotation and Reuse Detection to protect against token theft and session hijacking.
*   **Flexible JWT Algorithms:** Supports both symmetric (`HS256`) and asymmetric (`RS256`) algorithms out of the box.
*   **Zero-Downtime Key Rotation:** Built-in support for JWT Key Rotation (`kid`) to allow for seamless, zero-downtime secret updates.
*   **Multi-Factor Authentication (MFA):** Easily add a second factor of authentication to your sign-in flow.
*   **Built-in CSRF Protection:** Double Submit Cookie pattern to protect your Server Actions from Cross-Site Request Forgery, enabled by default.
*   **Rate Limiting:** Pluggable rate-limiting support to protect against brute-force attacks on sign-in.
*   **Declarative Protection Guards:** Secure your application with a single line of code using `protectPage()`, `protectAction()`, and `protectApi()`.
*   **Optimized Performance:** Middleware-based request-level caching automatically prevents redundant database checks.
*   **Flexible Authorization:** Implement role-based (RBAC) or attribute-based (ABAC) access control with a simple `authorize` callback.
*   **Extensible:** Supports social/OAuth providers, custom logging, and customizable error messages.
*   **Session Versioning:** Instantly invalidate all of a user's sessions from the server-side.
*   **Next.js Ready:** Built for the App Router, with first-class support for Server Components, Actions, API Routes, and Middleware.

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
Must include `version` and `isForbidden`. For MFA, add `hasMFA`.

```sql
CREATE TABLE `users` (
  -- ... other user columns (userId, email, passwordHash, etc.)
  `version` INT UNSIGNED NOT NULL DEFAULT 1,
  `isForbidden` BOOLEAN NOT NULL DEFAULT FALSE,
  `hasMFA` BOOLEAN NOT NULL DEFAULT FALSE
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
> **Note:** You should run a scheduled job to periodically delete expired JTIs: `DELETE FROM revokedTokens WHERE expiresAt < NOW();`.

---

## Quick Start

### 1. Define your User Identity and DAL

Implement the `UserIdentityDAL` interface to connect the library to your database.

```ts
// src/lib/auth-dal.ts
import type { UserIdentity, UserIdentityDAL } from "@waelhabbaldev/next-jwt-auth";
import db from "./db"; // Your database client

export interface AppUserIdentity extends UserIdentity {
  userId: number;
  username: string;
}

export const authDal: UserIdentityDAL<AppUserIdentity> = {
  async fetchIdentityByCredentials(username, password) { /* ... */ },
  async fetchIdentityForSession(identifier) { /* ... */ },
  async invalidateAllSessionsForIdentity(identifier) { /* ... */ },
  async isTokenJtiUsed(jti) { /* ... */ },
  async markTokenJtiAsUsed(jti, expirationInSeconds) { /* ... */ },
  async verifyMFA(identifier, code) { /* Optional: Implement TOTP logic */ return true; },
};
```

### 2. Configure and Export the Auth Instance

Create a central file (`src/lib/auth.ts`) to configure your `auth` object.

```ts
// src/lib/auth.ts
import { createAuth } from "@waelhabbaldev/next-jwt-auth";
import { authDal, AppUserIdentity } from "./auth-dal";
import { checkRateLimit } from "./rate-limiter"; // Your rate limit logic

export const auth = createAuth<AppUserIdentity>({
  // Required
  dal: authDal,
  baseUrl: process.env.BASE_URL!, // Used for creating absolute redirect URLs
  secrets: {
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET!,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  },
  
  cookies: {
    access: { name: "__at", maxAge: 15 * 60 },
    refresh: { name: "__rt", maxAge: 30 * 24 * 60 * 60 },
    csrf: { name: "csrf_token" }
  },

  redirects: {
    unauthenticated: "/signin",
    unauthorized: "/dashboard?error=unauthorized",
    forbidden: "/signin?error=forbidden",
  },
  
  // Recommended Security Features
  refreshTokenRotationIntervalSeconds: 7 * 24 * 60 * 60, // 7 days
  csrfEnabled: true,
  
  // Optional Features
  rateLimit: checkRateLimit,
  debug: process.env.NODE_ENV === "development",
});
```

### 3. Set Up Middleware for Session Management

The middleware is **essential** for session refreshing and performance caching.

```ts
// middleware.ts
import { auth } from "./lib/auth";

export default auth.createMiddleware();

export const config = {
  runtime: 'nodejs',
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
```

---

## Protecting Your Application

### Protecting Pages and Layouts

Use `auth.protectPage()` to secure any Server Component.

```tsx
// app/dashboard/layout.tsx
import { auth } from "@/lib/auth";

export default async function DashboardLayout({ children }) {
  const session = await auth.protectPage();
  // `session.identity` is guaranteed to be valid and available here.
  return <main>{children}</main>;
}
```

### Protecting Server Actions

Use `auth.protectAction()` or `auth.createProtectedAction()` to secure Server Actions. This automatically validates the CSRF token if `csrfEnabled` is true.

```ts
// app/actions.ts
"use server";
import { auth } from "@/lib/auth";
import { CsrfError } from "@waelhabbaldev/next-jwt-auth";

export async function sensitiveAction(formData: FormData) {
  try {
    const session = await auth.protectAction(undefined, formData);
    // ... logic for the action ...
  } catch (error) {
    if (error instanceof CsrfError) { /* handle CSRF error */ }
    // ...
  }
}
```

#### CSRF Protection with Forms

For forms using Server Actions, you must provide a CSRF token. This is done by generating the token on the server page and passing it to a Client Component via a provider.

**1. Generate the token in your Server Page/Component:**

```tsx
// app/signin/page.tsx (Server Component)
import { auth } from '@/lib/auth';
import { CsrfProvider } from '@waelhabbaldev/next-jwt-auth/client';
import { YourClientFormComponent } from './your-client-form';

export default async function SignInPage() {
  const csrfToken = await auth.getCsrfToken();

  return (
    <CsrfProvider token={csrfToken}>
      <YourClientFormComponent />
    </CsrfProvider>
  );
}
```

**2. Use the `CsrfInput` in your Client Component form:**

The `<CsrfInput /` component is designed for maximum ease of use. Simply place it in your form. It will automatically fetch the required token.

**1. Define a Server Action to get the token:**

```ts
// app/auth/actions.ts
"use server";
import { auth } from "@/lib/auth";

export async function getCsrfTokenAction() {
  return auth.getCsrfToken();
}
```

**2. Use `CsrfInput` in your form:**

```tsx
// your-form-component.tsx
"use client";
import { CsrfInput } from "@waelhabbaldev/next-jwt-auth/client";
import { getCsrfTokenAction } from "@/app/auth/actions";

export function MyForm() {
  return (
    <form action={...}
      <CsrfInput getTokenAction={getCsrfTokenAction} /
      {/* ... rest of your form */}
    </form
  );
}
```

### Protecting API Routes

Use `auth.protectApi()`. On failure, it returns a `response` object that you must return.

```ts
// app/api/projects/[id]/route.ts
import { auth } from "@/lib/auth";
import { NextResponse } from "next/server";

export async function GET(req, { params }) {
  const { session, response } = await auth.protectApi();
  if (response) return response; // Auth check failed, return the error response.

  // `session` is guaranteed to be valid here.
  return NextResponse.json({ data: "secret" });
}
```

---

## Client-Side Usage (React Hooks & Components)

This library provides React components and hooks for managing authentication state in Client Components. These must be imported from the `/client` entry point.

```ts
import { AuthProvider, useAuth, CsrfProvider, CsrfInput } from '@waelhabbaldev/next-jwt-auth/client';
```

### Setting up `AuthProvider`

Wrap your application layout with `AuthProvider` to make the session available globally via the `useAuth` hook.

**1. Create a client-side provider wrapper:**

```ts
// app/providers.tsx
'use client';
import { AuthProvider } from '@waelhabbaldev/next-jwt-auth/client';

// Define server actions to fetch and refresh the session for the client
async function sessionFetcher() {
  'use server';
  const { getSession } = await import('@/lib/auth');
  return getSession();
}

async function signOutAction() {
  'use server';
  const { signOut } = await import('@/lib/auth');
  await signOut();
}

export function Providers({ children }) {
  return (
    <AuthProvider sessionFetcher={sessionFetcher} signOutAction={signOutAction}>
      {children}
    </AuthProvider>
  );
}
```

**2. Use the provider in your root layout:**

```tsx
// app/layout.tsx
import { Providers } from './providers';

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
```

### Using the `useAuth` Hook

Now, any Client Component can access the session state.

```tsx
// components/user-button.tsx
'use client';
import { useAuth } from '@waelhabbaldev/next-jwt-auth/client';

export function UserButton() {
  const { identity, isAuthenticated, isLoading, signOut } = useAuth();

  if (isLoading) return <div>Loading...</div>;
  if (!isAuthenticated) return <a href="/signin">Sign In</a>;

  return (
    <div>
      <span>Welcome, {identity.username}!</span>
      <button onClick={() => signOut()}>Sign Out</button>
    </div>
  );
}
```

---

## API Reference

### Server-Side API (`@waelhabbaldev/next-jwt-auth`)

| Method                | Description                                                          |
| --------------------- | -------------------------------------------------------------------- |
| `createAuth()`        | Creates and configures the main authentication instance.             |
| `protectPage()`       | Secures Pages/Layouts. Redirects on failure.                         |
| `protectAction()`     | Secures Server Actions. Throws errors on failure.                    |
| `protectApi()`        | Secures API Routes. Returns a `Response` object on failure.          |
| `getSession()`        | **(Fast)** Fetches the session without protection. Reads from cache. |
| `getCsrfToken()`      | Generates a CSRF token for use with `CsrfProvider`.                  |
| `createMiddleware()`  | **(Essential)** Creates the middleware for session management.       |
| `signIn()`            | Signs in a user and sets session cookies.                            |
| `signOut()`           | Signs out a user and invalidates their session family.               |

### Client-Side API (`@waelhabbaldev/next-jwt-auth/client`)

| Component/Hook    | Description                                                                     |
| ----------------- | ------------------------------------------------------------------------------- |
| `AuthProvider`    | React Context provider for making session state available to Client Components. |
| `useAuth()`       | React hook to access session state (`identity`, `isAuthenticated`, etc.).       |
| `CsrfProvider`    | Provides a CSRF token to descendant components.                                 |
| `CsrfInput`       | A hidden input field that automatically includes the CSRF token in a form.      |

---

## Keywords

`nextjs`, `authentication`, `authorization`, `jwt`, `auth`, `security`, `rbac`, `abac`, `session-management`, `access-token`, `refresh-token`, `middleware`, `mfa`, `oauth`, `rate-limiting`, `csrf`, `key-rotation`, `nextjs-auth`, `app-router`, `jose`

---

## License

MIT License