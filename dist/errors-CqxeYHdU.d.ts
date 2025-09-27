interface CookieOptions {
    name: string;
    value: string;
    maxAge?: number;
    expires?: Date;
    httpOnly?: boolean;
    secure?: boolean;
    domain?: string;
    path?: string;
    sameSite?: "strict" | "lax" | "none";
}
interface UserIdentity {
    identifier: string;
    roles: string[];
    version: number;
    isForbidden: boolean;
}
type PublicUserIdentity<T extends UserIdentity> = Omit<T, "version" | "isForbidden">;
type RefreshTokenPayload = {
    identifier: string;
    version: number;
    jti: string;
    iat?: number;
};
type AuthSession<T extends UserIdentity> = {
    identity: PublicUserIdentity<T>;
} | null;
interface TokenPair {
    accessToken: string;
    refreshToken: string;
}
interface AuthCookieConfig extends Partial<CookieOptions> {
    name: string;
    value: string;
    maxAge?: number;
}
interface UserIdentityDAL<T extends UserIdentity> {
    fetchIdentityByCredentials: (signInIdentifier: string, secret: string) => Promise<T | null>;
    fetchIdentityForSession: (identifier: string) => Promise<T | null>;
    invalidateAllSessionsForIdentity: (identifier: string) => Promise<void>;
    isTokenJtiUsed: (jti: string) => Promise<boolean>;
    markTokenJtiAsUsed: (jti: string, expirationInSeconds: number) => Promise<void>;
}

/**
 * @module @waelhabbaldev/next-jwt-auth/errors
 * This module exports custom error classes used throughout the authentication package.
 * Using these specific classes allows for granular error handling in Server Actions and other server-side logic.
 */
/**
 * Base error class for all authentication and authorization related errors
 * within the package. You can use `instanceof AuthError` to catch any
 * error originating from this library.
 */
declare class AuthError extends Error {
    constructor(message: string);
}
/**
 * Thrown by the `signIn` function when the provided credentials
 * (e.g., email/password) do not match any user in the database.
 */
declare class InvalidCredentialsError extends AuthError {
    constructor();
}
/**
 * Thrown by the `signIn` function if a user is found but their
 * `isForbidden` flag is set to true in the database. This allows for
 * banning or suspending user accounts.
 */
declare class IdentityForbiddenError extends AuthError {
    constructor();
}
/**
 * Thrown by protection helpers (like `protectAction`) when a request is made
 * by a user who is not authenticated (i.e., has no valid session).
 * This is the primary error for unauthenticated access to protected server actions.
 */
declare class NotAuthenticatedError extends AuthError {
    constructor();
}
/**
 * Thrown by protection helpers (like `protectAction`) when a user is
 * authenticated but does not meet the specific authorization criteria
 * defined in the `authorize` callback (e.g., missing a required role or claim).
 */
declare class ForbiddenError extends AuthError {
    constructor(message?: string);
}

export { type AuthSession as A, type CookieOptions as C, ForbiddenError as F, InvalidCredentialsError as I, NotAuthenticatedError as N, type PublicUserIdentity as P, type RefreshTokenPayload as R, type TokenPair as T, type UserIdentity as U, type UserIdentityDAL as a, type AuthCookieConfig as b, AuthError as c, IdentityForbiddenError as d };
