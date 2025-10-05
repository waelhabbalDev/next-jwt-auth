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
*   **CSRF Protection:** Optional Double Submit Cookie pattern to protect your Server Actions from Cross-Site Request Forgery.
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
  baseUrl: process.env.BASE_URL!, 
  secrets: {
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET!,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  },
  cookies: {
    access: { name: "__at", maxAge: 15 * 60 },
    refresh: { name: "__rt", maxAge: 30 * 24 * 60 * 60 },
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

// This handles all session validation and token refreshing automatically.
export default auth.createMiddleware();

export const config = {
  // IMPORTANT: If your UserIdentityDAL performs database queries (which it almost
  // always will), you MUST export this line to force the middleware to use the
  // Node.js runtime. The Edge runtime does not support most database drivers.
  
  // 📢 📢 this will need the most recent nextjs, I tested it on version 15.6.0-canary 
  runtime = 'nodejs',
  // Match all paths except for static assets.
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
```
> **How it works:** The middleware runs a full auth check on every request. If the session is valid, it attaches the user's identity to a request header. This allows subsequent calls to `getSession()` or `protectPage()` to be **near-instantaneous, cached reads**, preventing database waterfalls.

---

## Protecting Your Application

### Protecting Pages and Layouts
Use `auth.protectPage()` to secure any Server Component. It will automatically redirect unauthenticated users.

```tsx
// app/dashboard/layout.tsx
import { auth } from "@/lib/auth";

export default async function DashboardLayout({ children }) {
  // This validates the session and redirects if invalid.
  // Thanks to the middleware, this is a fast, in-memory check.
  const session = await auth.protectPage();
  
  // You can now safely use session.identity
  return <main>{children}</main>;
}
```

### Protecting Server Actions
Use `auth.protectAction()`. If `csrfEnabled` is true, it will automatically validate the CSRF token.

```ts
// app/actions.ts
"use server";
import { auth } from "@/lib/auth";
import { NotAuthenticatedError, CsrfError } from "@waelhabbaldev/next-jwt-auth";

export async function sensitiveAction(formData: FormData) {
  try {
    const session = await auth.protectAction();
    // ... logic ...
  } catch (error) {
    if (error instanceof CsrfError) { /* handle CSRF error */ }
    if (error instanceof NotAuthenticatedError) { /* handle auth error */ }
    // ...
  }
}
```
On the client, you must read the `csrf_token` cookie and send it in the `x-csrf-token` header with your request.

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

## Advanced Usage: Asymmetric Keys (RS256)

For advanced architectures, you can use `RS256` with public/private key pairs.

```ts
// src/lib/auth.ts
import { createPrivateKey } from "crypto";

const privateKey = createPrivateKey(process.env.PRIVATE_KEY!);

export const auth = createAuth({
  // ...
  secrets: {
    accessTokenSecret: privateKey,
    refreshTokenSecret: privateKey, // Recommended: use a separate key pair
  },
  jwt: {
    alg: 'RS256',
  },
});
```
> **Verification in other services:** To verify a token in a different microservice, you would use the corresponding **public key** as the secret in that service's `verifyAccessToken` call.

---

## API Reference

| Method             | Description                                                                                             | Failure Behavior |
| ------------------ | ------------------------------------------------------------------------------------------------------- | ---------------- |
| `protectPage()`    | Secures Pages/Layouts with optional authorization. Redirects on failure.                                | Redirects        |
| `protectAction()`  | Secures Server Actions. Supports CSRF. Throws specific errors on failure.                               | Throws Error     |
| `protectApi()`     | Secures API Routes. Returns an error `response` object on failure.                                      | Returns Response |
| `getSession()`     | **(Fast)** Fetches the session without protection. Reads from middleware cache.                           | Returns `null`   |
| `refreshSession()` | Manually triggers a session refresh on the server. Useful for client-side error recovery.               | Throws Error     |
| `signIn()`         | Signs in a user (credentials, provider, or MFA) and sets session cookies.                               | Throws Error     |
| `signOut()`        | Signs out a user and invalidates their entire session family.                                           | (N/A)            |
| `createMiddleware()`| **(Essential)** Creates the middleware for session management and caching.                              | (Internal)       |

---

## Keywords

`nextjs`, `authentication`, `authorization`, `jwt`, `auth`, `security`, `rbac`, `abac`, `session-management`, `access-token`, `refresh-token`, `middleware`, `mfa`, `oauth`, `rate-limiting`, `csrf`, `key-rotation`, `nextjs-auth`, `app-router`, `jose`

---

## License

MIT License