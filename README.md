
# @waelhabbalDev/next-jwt-auth

[![NPM Version](https://img.shields.io/npm/v/@waelhabbaldev/next-jwt-auth.svg)](https://www.npmjs.com/package/@waelhabbaldev/next-jwt-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<img src="icons/icon.svg" alt="Nextjs JWT Auth" width="256" height="256">

**Next.js JWT Authentication Made Easy**
A lightweight, secure, and performance-optimized authentication library for Next.js using JWT access and refresh tokens. Supports token rotation, secure cookie storage, middleware integration, and React hooks for seamless client-side session management.

---

## Features

* **JWT-based Authentication:** Access and refresh tokens for secure sessions.
* **Automatic Token Rotation:** Configurable rotation strategies for enhanced security.
* **Middleware Integration:** Protect server-side routes easily with reusable middleware.
* **React Hooks & Context:** Simple client-side session handling with `useAuth` and `AuthProvider`.
* **Secure Cookies:** HttpOnly, Secure, and SameSite cookies for tokens.
* **DAL Agnostic:** Plug in your database logic via a simple interface.
* **Next.js Ready:** Works with App Router, API routes, and Server Components.

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

## Quick Start

### 1. Configure Authentication

```ts
// src/auth.ts
import { createAuth } from "@waelhabbalDev/next-jwt-auth";
import { UserIdentityDAL } from "./types";

const dal: UserIdentityDAL<any> = {
  fetchIdentityByCredentials: async (identifier, secret) => { /* DB fetch */ },
  fetchIdentityForSession: async (identifier) => { /* DB fetch */ },
  invalidateAllSessionsForIdentity: async (identifier) => { /* DB logic */ },
  isTokenJtiUsed: async (jti) => false,
  markTokenJtiAsUsed: async (jti, expiration) => {},
};

export const auth = createAuth({
  dal,
  secrets: {
    accessTokenSecret: process.env.ACCESS_TOKEN_SECRET!,
    refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
  },
  cookies: {
    access: { name: "next-access", maxAge: 15 * 60 },
    refresh: { name: "next-refresh", maxAge: 7 * 24 * 60 * 60 },
  },
  jwt: {
    issuer: "your-app",
    audience: "your-app-users",
  },
  rotationStrategy: "always", // or "on-demand"
});
```

---

### 2. Sign In / Sign Out

```ts
// server actions
const user = await auth.signIn("email@example.com", "password123");
await auth.signOut();
```

---

### 3. Protect API Routes

```ts
// pages/api/protected.ts
import { auth } from "../../auth";

export default auth.createAuthMiddleware()(async (req, res) => {
  res.json({ message: "Protected route" });
});
```

---

### 4. Client-side Session with React

```tsx
// App.tsx
import { AuthProvider, useAuth } from "@waelhabbalDev/next-jwt-auth";

function App({ children }) {
  return (
    <AuthProvider
      sessionFetcher={() => fetch("/api/auth-session").then(res => res.json())}
      signInAction={(id, pass) => fetch("/api/sign-in").then(res => res.json())}
      signOutAction={() => fetch("/api/sign-out")}
    >
      {children}
    </AuthProvider>
  );
}

// Usage in component
function Profile() {
  const { identity, isAuthenticated, signOut } = useAuth();

  if (!isAuthenticated) return <p>Please login</p>;

  return (
    <div>
      <h1>Hello {identity?.identifier}</h1>
      <button onClick={signOut}>Logout</button>
    </div>
  );
}
```

---

## API

### `createAuth(config)`

Creates an authentication instance.

**Config Options:**

| Key              | Type                                        | Description                                                   |                                                     |
| ---------------- | ------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------- |
| dal              | UserIdentityDAL                             | Database abstraction layer for fetching and validating users. |                                                     |
| secrets          | `{ accessTokenSecret, refreshTokenSecret }` | Secrets for signing JWTs. Must be ≥32 characters.             |                                                     |
| cookies          | `{ access, refresh }`                       | Cookie configurations with `name` and `maxAge` in seconds.    |                                                     |
| jwt              | `{ issuer?, audience? }`                    | Optional JWT issuer and audience.                             |                                                     |
| rotationStrategy | `"always"                                   | "on-demand"`                                                  | When to rotate refresh tokens. Default: `"always"`. |

**Returns:** `{ getAuthSession, signIn, signOut, createAuthMiddleware }`

---

### `getAuthSession(req?)`

Fetches current session. If called server-side, will also refresh tokens automatically.

---

### `signIn(identifier, secret)`

Signs in a user, issues tokens, and sets cookies.

---

### `signOut()`

Signs out a user, clears cookies, and invalidates refresh tokens in DB.

---

### `createAuthMiddleware(matcher?)`

Middleware for protecting server-side routes.

```ts
const middleware = auth.createAuthMiddleware(req => req.nextUrl.pathname.startsWith("/api/protected"));
```

---

## Security

* Tokens are stored in **HttpOnly**, **Secure**, and **SameSite=Strict** cookies.
* **Refresh token reuse detection** invalidates all sessions for a compromised user.
* **Token rotation** prevents long-lived refresh tokens from being exploited.

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

---
