# @waelhabbalDev/next-jwt-auth

[![NPM Version](https://img.shields.io/npm/v/@waelhabbaldev/next-jwt-auth.svg)](https://www.npmjs.com/package/@waelhabbaldev/next-jwt-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<div align="center">
  <img src="icons/icon.svg" alt="Next.js JWT Auth" width="256" height="256">
</div>

<h3 align="center">Next.js JWT Authentication Made Easy</h3>

A lightweight, secure, and performance-optimized authentication library for Next.js 14+ (App Router). It implements a robust security model using JWT access and refresh tokens with automatic token rotation and reuse detection.

---

## Features

*   **State-of-the-Art Security:** Automatic Refresh Token Rotation and Reuse Detection to protect against token theft.
*   **Secure Cookie Storage:** Tokens are stored in `HttpOnly`, `Secure`, and `SameSite=Strict` cookies.
*   **Next.js 14+ Ready:** Built for the App Router. Works seamlessly with Server Components, Server Actions, Route Handlers, and Middleware.
*   **Type-Safe Hooks:** Generic React Hooks (`useAuth`) and Context (`AuthProvider`) for simple, type-safe client-side session management.
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

To use all security features of this library, your database schema must include the following:

### 1. Users Table
Your users table needs a numeric column to handle session invalidation. We recommend `tokenVersion`.

```sql
CREATE TABLE `users` (
  -- ... other user columns (userId, email, hashedPassword, etc.)
  `tokenVersion` INT NOT NULL DEFAULT 0,
  `isForbidden` BOOLEAN NOT NULL DEFAULT FALSE
);
```
-   **`tokenVersion`**: When you want to invalidate all sessions for a user (e.g., after a password change), simply increment this value. Any refresh token with an older version number will be rejected.
-   **`isForbidden`**: A boolean to easily ban or suspend a user account.

### 2. Used Refresh Tokens Table
To enable refresh token reuse detection, you need a table to store the JTI (JWT ID) of used refresh tokens.

```sql
CREATE TABLE `used_refresh_token_jtis` (
    `jti` VARCHAR(36) NOT NULL,
    `expiresAt` TIMESTAMP NOT NULL,
    PRIMARY KEY (`jti`)
);
```
-   **Why?** When a refresh token is used, its unique `jti` is stored here. If the same token is used again (a sign it may have been stolen), the system detects it, rejects the request, and invalidates all sessions for that user. You should run a scheduled job to clean up expired JTIs from this table.

---

## Quick Start

### 1. Define your User Identity and DAL

First, define a type for your user's identity that extends the base `UserIdentity`.

```ts
// src/lib/auth.types.ts
import type { UserIdentity } from "@waelhabbalDev/next-jwt-auth";

export interface AppUserIdentity extends UserIdentity {
  // identifier, roles, version, isForbidden are required by the base type
  fullName: string | null;
  email: string;
}
```

Next, implement the Data Access Layer (DAL) to connect the library to your database.

```ts
// src/lib/dal.ts
import { UserIdentityDAL } from "@waelhabbalDev/next-jwt-auth";
import { AppUserIdentity } from "./auth.types";
import db from "./db"; // Your database client (e.g., Prisma)

export const dal: UserIdentityDAL<AppUserIdentity> = {
  fetchIdentityByCredentials: async (email, password) => {
    const user = await db.users.findUserForAuth(email, password);
    if (!user) return null;
    return {
      identifier: user.userId,
      fullName: user.fullName,
      email: user.email,
      roles: [user.role], // roles must be an array of strings
      version: user.tokenVersion,
      isForbidden: user.isForbidden,
    };
  },
  fetchIdentityForSession: async (identifier) => {
    // Fetches user by ID for session validation and token refresh
    const user = await db.users.findUserForSession(identifier);
    if (!user) return null;
    // ... map user to AppUserIdentity ... 
    return {
      identifier: user.userId,
      fullName: user.fullName,
      email: user.email,
      roles: [user.role],
      version: user.tokenVersion,
      isForbidden: user.isForbidden,
    };
  },
  invalidateAllSessionsForIdentity: async (identifier) => {
    // Increments the user's `tokenVersion` in the DB
    await db.users.incrementTokenVersion(identifier);
  },
  isTokenJtiUsed: async (jti) => {
    // Check if the JTI exists in your `used_refresh_token_jtis` table
    return await db.jtis.isTokenJtiUsed(jti);
  },
  markTokenJtiAsUsed: async (jti, expiration) => {
    // Add the JTI to your `used_refresh_token_jtis` table with an expiry
    await db.jtis.markTokenJtiAsUsed(jti, expiration);
  },
};
```

### 2. Configure and Export the Auth Instance

Create a central file to configure and export your `auth` object.

```ts
// src/lib/auth.ts
import { createAuth } from "@waelhabbalDev/next-jwt-auth";
import { dal } from "./dal";

export const auth = createAuth({
  dal,
  secrets: {
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET!,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  },
  cookies: {
    access: { name: "auth-access-token", maxAge: 15 * 60 },       // 15 minutes
    refresh: { name: "auth-refresh-token", maxAge: 7 * 24 * 60 * 60 }, // 7 days
  },
  rotationStrategy: "always", // "always" is recommended for max security
});
```

### 3. Set Up Middleware for Token Refresh

The middleware is crucial for keeping the user's session alive by refreshing tokens automatically.

```ts
// middleware.ts
import { type NextRequest } from "next/server";
import { auth } from "@/lib/auth";

// The auth middleware handles token refreshing.
// You can chain it with other middlewares (e.g., for localization or authorization).
export default auth.createAuthMiddleware();

export const config = {
  // Match all paths except for static assets and API routes.
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
```

### 4. Wrap Your App in the `AuthProvider`

Create an API route for the session and wrap your application in the provider.

```ts
// app/api/auth/session/route.ts
import { auth } from "@/lib/auth";
import { NextResponse } from "next/server";

export async function GET() {
  const session = await auth.getAuthSession(); // Handles refresh
  return NextResponse.json(session);
}
```

```tsx
// app/providers.tsx
"use client";
import { AuthProvider } from "@waelhabbalDev/next-jwt-auth";
import { signInAction, signOutAction } from "@/app/actions/authActions"; // Your server actions

export function Providers({ children }) {
  return (
    <AuthProvider
      sessionFetcher={() => fetch("/api/auth/session").then((res) => res.json())}
      signInAction={signInAction} // Pass the server action directly
      signOutAction={signOutAction}
    >
      {children}
    </AuthProvider>
  );
}
```

```tsx
// app/layout.tsx
import { Providers } from "./providers";

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
```

### 5. Use the Session

Now you can access the session anywhere in your app.

```tsx
// Server Component
import { auth } from "@/lib/auth";

async function MyServerComponent() {
  const session = await auth.getAuthSession();
  if (!session) return <p>Not authenticated</p>;
  return <p>Welcome, {session.identity.fullName}</p>;
}
```

```tsx
// Client Component
"use client";
import { useAuth } from "@waelhabbalDev/next-jwt-auth";
import { AppUserIdentity } from "@/lib/auth.types"; // Your custom type

function Profile() {
  // Specify your custom identity type for full type-safety
  const { identity, signOut, error } = useAuth<AppUserIdentity>();

  if (error) return <p>Session error: {error.message}</p>
  if (!identity) return <p>Please login</p>;

  return (
    <div>
      <h1>Hello, {identity.fullName}</h1>
      <button onClick={signOut}>Logout</button>
    </div>
  );
}
```

---

## API Reference

### `createAuth(config)`
Creates an authentication instance. See config options above.
**Returns:** `{ getAuthSession, signIn, signOut, createAuthMiddleware }`

---

### `getAuthSession()`
Fetches the current session **for Server Components and Server Actions**. Automatically handles token rotation and sets new cookies. Returns `Promise<AuthSession<T> | null>`.

---

### `signIn(identifier, secret)`
Signs in a user, issues tokens, and sets cookies. Called from a Server Action. Returns the user's public identity.

---

### `signOut()`
Signs out a user, clears cookies, and invalidates the current refresh token family by incrementing the `tokenVersion` in the database.

---

### `createAuthMiddleware(matcher?)`
Creates Next.js middleware that automatically refreshes tokens on navigation for authenticated users, keeping sessions alive. The `matcher` function is optional and defaults to all routes.

---

## Security
*   **Refresh Token Rotation:** Mitigates damage from a leaked refresh token. When a new access/refresh token pair is issued, the refresh token used is invalidated.
*   **Reuse Detection:** If a compromised (and already used) refresh token is presented, the library detects it, immediately invalidates **all** active sessions for that user, and logs them out everywhere.
*   **Secure Cookies:** All tokens are stored in `HttpOnly`, `Secure` (in production), and `SameSite=Strict` cookies to protect against XSS and CSRF attacks.

---

## Recommended Environment Variables

```env
ACCESS_TOKEN_SECRET="your-32+char-secret"
REFRESH_TOKEN_SECRET="your-32+char-secret"
NODE_ENV="production"
```

---

## Keywords

`nextjs`, `jwt`, `authentication`, `auth`, `secure-sessions`, `access-token`, `refresh-token`, `middleware`, `react-hooks`, `token-rotation`

---

## License

MIT License