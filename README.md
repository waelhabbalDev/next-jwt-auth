# @waelhabbaldev/next-jwt-auth

[![NPM Version](https://img.shields.io/npm/v/@waelhabbaldev/next-jwt-auth.svg)](https://www.npmjs.com/package/@waelhabbaldev/next-jwt-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<div align="center">
  <img src="icons/icon.svg" alt="Next.js JWT Auth" width="256" height="256">
</div>

<h3 align="center">Declarative, Secure, Enterprise-Grade Authentication for Next.js</h3>

A lightweight, secure, and performance-optimized authentication library for the Next.js App Router. It implements a robust, multi-layered security model using JWTs and provides a simple, declarative API to protect your pages, server actions, and API routes.

---

## Features

*   **State-of-the-Art Security:** Automatic Refresh Token Rotation and JTI-based Reuse Detection to protect against token theft and session hijacking.
*   **Flexible JWT Algorithms:** Supports both symmetric (`HS256`) and asymmetric (`RS256`) algorithms out of the box.
*   **Zero-Downtime Key Rotation:** Built-in support for JWT Key Rotation (`kid`) to allow for seamless, zero-downtime secret updates.
*   **Multi-Factor Authentication (MFA):** Easily add a second factor of authentication (e.g., TOTP) to your sign-in flow.
*   **Built-in CSRF Protection:** Double Submit Cookie pattern automatically protects all Server Actions from Cross-Site Request Forgery.
*   **Rate Limiting:** Pluggable rate-limiting support to protect your `signIn` endpoint against brute-force attacks.
*   **Declarative Protection Guards:** Secure your application with a single line of code using `protectPage()`, `protectAction()`, and `protectApi()`.
*   **Optimized for Performance:** Middleware-based session validation and request-level caching (`React.cache`) automatically prevent redundant database calls.
*   **Flexible Authorization:** Implement Role-Based (RBAC) or Attribute-Based (ABAC) access control with a simple `authorize` callback in any protection guard.
*   **Extensible:** Supports social/OAuth providers, custom logging, and customizable error messages.
*   **Session Versioning:** Instantly invalidate all of a user's sessions from the server-side by incrementing a `version` number in the database.
*   **Next.js Ready:** Built for the App Router with first-class support for Server Components, Server Actions, API Routes, and Middleware.

---

## Installation

```bash
bun add @waelhabbaldev/next-jwt-auth jose
# or
npm install @waelhabbaldev/next-jwt-auth jose
# or
yarn add @waelhabbaldev/next-jwt-auth jose
```

> **Note:** `jose` is a peer dependency and must be installed alongside the package.

---

## Database Schema Requirements

Your database needs two tables to support all security features.

#### 1. `users` Table
Must include `version` and `isForbidden` columns. For MFA, add `hasMFA`.

```sql
CREATE TABLE `users` (
  -- ... other user columns (id, email, passwordHash, etc.)
  `version` INT UNSIGNED NOT NULL DEFAULT 1,
  `isForbidden` BOOLEAN NOT NULL DEFAULT FALSE,
  `hasMFA` BOOLEAN NOT NULL DEFAULT FALSE
);
```

#### 2. `revokedTokens` Table
Required for Refresh Token Reuse Detection, the core defense against token theft.

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

Implement the `UserIdentityDAL` interface to connect the library to your database. This is the bridge between the auth logic and your data.

```ts
// src/lib/auth-dal.ts
import type { UserIdentity, UserIdentityDAL } from "@waelhabbaldev/next-jwt-auth";
import db from "./db"; // Your database client
import { compare } from "bcrypt"; // Example password hashing library

// Define a type for your user identity that extends the base UserIdentity
export interface AppUserIdentity extends UserIdentity {
  id: number;
  email: string;
}

export const authDal: UserIdentityDAL<AppUserIdentity> = {
  // Find a user by their credentials (e.g., email and password)
  async fetchIdentityByCredentials(email, password) {
    const user = await db.user.findUnique({ where: { email } });
    if (!user) return null;

    const isPasswordValid = await compare(password, user.passwordHash);
    if (!isPasswordValid) return null;

    // Return the full user identity object on success
    return { ...user, roles: user.roles.split(',') };
  },

  // Find a user for an existing session
  async fetchIdentityForSession(identifier) {
    const user = await db.user.findUnique({ where: { id: Number(identifier) } });
    if (!user) return null;
    return { ...user, roles: user.roles.split(',') };
  },

  // Invalidate all sessions by incrementing the user's version
  async invalidateAllSessionsForIdentity(identifier) {
    await db.user.update({
      where: { id: Number(identifier) },
      data: { version: { increment: 1 } },
    });
  },

  // Check if a JTI has been used (replay attack defense)
  async isTokenJtiUsed(jti) {
    const token = await db.revokedToken.findUnique({ where: { jti } });
    return !!token;
  },

  // Mark a JTI as used
  async markTokenJtiAsUsed(jti, expirationInSeconds) {
    const expiresAt = new Date(Date.now() + expirationInSeconds * 1000);
    await db.revokedToken.create({ data: { jti, expiresAt } });
  },

  // Optional: Implement your TOTP or other MFA verification logic
  async verifyMFA(identifier, code) {
    // Example: const isValid = totp.verify({ token: code, ... });
    return true;
  },
};
```

### 2. Configure and Export the Auth Instance

Create a central file (`src/lib/auth.ts`) to configure your `auth` object. **Store secrets in environment variables.**

```ts
// src/lib/auth.ts
import { createAuth } from "@waelhabbaldev/next-jwt-auth";
import { authDal, AppUserIdentity } from "./auth-dal";
import { checkRateLimit } from "./rate-limiter"; // Your rate limit logic

export const {
  createMiddleware,
  getSession,
  getCsrfToken,
  signIn,
  signOut,
  protectPage,
  protectAction,
  protectApi,
} = createAuth<AppUserIdentity>({
  // Required
  dal: authDal,
  baseUrl: process.env.BASE_URL!, // e.g., "http://localhost:3000"
  secrets: {
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET!,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  },
  
  cookies: {
    access: { name: "__at", maxAge: 15 * 60 }, // 15 minutes
    refresh: { name: "__rt", maxAge: 30 * 24 * 60 * 60 }, // 30 days
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

The middleware is **essential** for handling automatic session refreshing and caching identity for performance.

```ts
// middleware.ts
import { createMiddleware } from "./lib/auth";

export default createMiddleware();

export const config = {
  /**
   * Forces 'nodejs' runtime. Required for full Node.js APIs (e.g., database clients) 
   * as the default 'edge' runtime restricts I/O and networking features.
 */
  runtime:'nodejs',
  // Match all paths except for static assets and API routes.
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
```

---

## Protecting Your Application

### Protecting Pages and Layouts

Use `protectPage()` to secure any Server Component. It guarantees a valid session or redirects.

```tsx
// app/dashboard/layout.tsx
import { protectPage } from "@/lib/auth";

export default async function DashboardLayout({ children }) {
  const session = await protectPage();
  // `session.identity` is guaranteed to be valid and available here.
  return <main>{children}</main>;
}
```

### Protecting Server Actions

Use `protectAction()` to secure Server Actions. This **automatically validates the CSRF token**.

```ts
// app/actions.ts
"use server";
import { protectAction } from "@/lib/auth";
import { CsrfError } from "@waelhabbaldev/next-jwt-auth";

export async function sensitiveAction(formData: FormData) {
  try {
    // Pass the formData to enable the automatic CSRF check.
    const session = await protectAction(undefined, formData);
    // User is authenticated and authorized.
    // ... logic for the action ...
  } catch (error) {
    if (error instanceof CsrfError) {
      return { error: "Invalid CSRF token." };
    }
    // Handle other auth errors (NotAuthenticatedError, ForbiddenError)
  }
}
```

#### CSRF Protection with Forms

For forms using Server Actions, you must provide the CSRF token. This is done by generating the token on the server page and passing it to a Client Component.

**1. Generate the token in your Server Page/Component:**

```tsx
// app/settings/page.tsx (Server Component)
import { getCsrfToken } from '@/lib/auth';
import { CsrfProvider } from '@waelhabbaldev/next-jwt-auth/client';
import { SettingsForm } from './settings-form'; // Your form is a Client Component

export default async function SettingsPage() {
  const csrfToken = await getCsrfToken();

  return (
    <CsrfProvider token={csrfToken}>
      <SettingsForm />
    </CsrfProvider>
  );
}
```

**2. Use the `CsrfInput` in your Client Component form:**

Place the `<CsrfInput />` component inside your form. It automatically reads the token from the provider.

```tsx
// components/settings-form.tsx (Client Component)
"use client";
import { CsrfInput } from "@waelhabbaldev/next-jwt-auth/client";
import { sensitiveAction } from "@/app/actions";

export function SettingsForm() {
  return (
    <form action={sensitiveAction}>
      <CsrfInput />
      {/* ... rest of your form inputs */}
      <button type="submit">Save</button>
    </form>
  );
}
```

### Protecting API Routes

Use `protectApi()`. On failure, it returns a `response` object that you must immediately return.

```ts
// app/api/projects/[id]/route.ts
import { protectApi } from "@/lib/auth";
import { NextResponse } from "next/server";

export async function GET(req, { params }) {
  const result = await protectApi();
  
  // If `response` is present, auth failed. Return it.
  if (result.response) return result.response;
  
  // `result.session` is guaranteed to be valid here.
  const { session } = result;
  
  return NextResponse.json({ data: `secret data for ${session.identity.email}` });
}
```

---

## Client-Side Usage (React Hooks & Components)

This library provides React components and hooks for managing authentication state in Client Components. These must be imported from the `/client` entry point.

```ts
import { AuthProvider, useAuth } from '@waelhabbaldev/next-jwt-auth/client';
```

### Setting up `AuthProvider`

Wrap your application layout with `AuthProvider` to make the session available globally.

**1. Create Server Actions for the client to use:**

```ts
// app/auth/actions.ts
'use server';
import { getSession, signIn, signOut } from '@/lib/auth';
import { AuthError } from '@waelhabbaldev/next-jwt-auth';

// Action to get the current session
export async function getSessionAction() {
  return getSession();
}

// Action to sign in
export async function signInAction(identifier: string, secret: string) {
  try {
    return await signIn(identifier, secret);
  } catch (error) {
    if (error instanceof AuthError) {
      // Re-throw specific auth errors to be handled by the client
      throw error;
    }
    throw new Error('An unknown error occurred.');
  }
}

// Action to sign out
export async function signOutAction() {
  return signOut();
}
```

**2. Create a client-side provider wrapper:**

```tsx
// app/providers.tsx
'use client';
import { AuthProvider } from '@waelhabbaldev/next-jwt-auth/client';
import { getSessionAction, signInAction, signOutAction } from '@/app/auth/actions';

export function Providers({ children }) {
  return (
    <AuthProvider
      sessionFetcher={getSessionAction}
      signInAction={signInAction}
      signOutAction={signOutAction}
    >
      {children}
    </AuthProvider>
  );
}
```

**3. Use the provider in your root layout:**

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

Now, any Client Component can access the authentication state and actions.

```tsx
// components/user-button.tsx
'use client';
import { useAuth } from '@waelhabbaldev/next-jwt-auth/client';

export function UserButton() {
  const { identity, isAuthenticated, isLoading, signOut } = useAuth<AppUserIdentity>();

  if (isLoading) return <div>Loading...</div>;

  if (!isAuthenticated) {
    return <a href="/signin">Sign In</a>;
  }

  return (
    <div>
      <span>Welcome, {identity.email}!</span>
      <button onClick={() => signOut()}>Sign Out</button>
    </div>
  );
}```

---

## API Reference

### Server-Side API (`@waelhabbaldev/next-jwt-auth`)

| Method                | Description                                                                 |
| --------------------- | --------------------------------------------------------------------------- |
| `createAuth()`        | Creates and configures the main authentication instance.                    |
| `protectPage()`       | Secures Pages/Layouts. Guarantees a session or redirects on failure.        |
| `protectAction()`     | Secures Server Actions. Throws `AuthError` on failure. Auto-validates CSRF. |
| `protectApi()`        | Secures API Routes. Returns a `{ session }` or `{ response }` object.       |
| `getSession()`        | **(Fast)** Gets the session without protection. Reads from cache. Can be `null`. |
| `getCsrfToken()`      | Generates a CSRF token for use with `CsrfProvider`.                         |
| `createMiddleware()`  | **(Essential)** Creates the middleware for session management and rotation. |
| `signIn()`            | Authenticates a user and sets session cookies.                              |
| `signOut()`           | Deletes session cookies and invalidates the user's sessions.                |
| `verifyAccessToken()` | A utility to verify an access token's signature without hitting the DB.     |

### Client-Side API (`@waelhabbaldev/next-jwt-auth/client`)

| Component/Hook | Description                                                                     |
| -------------- | ------------------------------------------------------------------------------- |
| `AuthProvider` | React Context provider for making session state available to Client Components. |
| `useAuth()`    | React hook to access session state (`identity`, `isAuthenticated`, `signIn`, `signOut`, etc.). |
| `CsrfProvider` | Provides a CSRF token (generated on the server) to descendant components.     |
| `CsrfInput`    | A hidden input that automatically includes the CSRF token in a form.            |

---

## Keywords

`nextjs`, `authentication`, `authorization`, `jwt`, `auth`, `security`, `rbac`, `abac`, `session-management`, `access-token`, `refresh-token`, `middleware`, `mfa`, `oauth`, `rate-limiting`, `csrf`, `key-rotation`, `nextjs-auth`, `app-router`, `jose`

---

## License

MIT License