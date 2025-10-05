import { KeyObject } from 'crypto';

/**
 * The core user identity structure that the DAL must return.
 * This contains sensitive, server-side-only information.
 */
interface UserIdentity {
    /** A unique, stable string identifier for the user (e.g., UUID or user ID). */
    identifier: string;
    /** An array of roles or permissions for authorization checks. */
    roles: string[];
    /** A version number used for immediate, global session invalidation. */
    version: number;
    /** A flag to globally disable an account. */
    isForbidden: boolean;
    /** A flag indicating if the user has MFA enabled. Optional for backward compatibility. */
    hasMFA?: boolean;
}
/**
 * The public-facing user identity, stripped of sensitive fields.
 * This is the object that is safe to expose to the client-side.
 */
type PublicUserIdentity<T extends UserIdentity> = Omit<T, "version" | "isForbidden">;
/**
 * Represents the authenticated session state.
 * It's either an object containing the public identity, or null if unauthenticated.
 */
type AuthSession<T extends UserIdentity> = {
    identity: PublicUserIdentity<T>;
} | null;
/**
 * Represents the secret used for signing and verifying JWTs.
 * - For symmetric algorithms like HS256, this is a `string`.
 * - For asymmetric algorithms like RS256, this is a `KeyObject` from Node's `crypto` module.
 * - To support key rotation, can be an object with key and optional kid, or an array for verification.
 */
type JWTSecret = string | {
    key: string | KeyObject;
    kid?: string;
} | {
    key: string | KeyObject;
    kid?: string;
}[];
/**
 * The payload structure for the refresh token JWT.
 * Contains only the necessary data for re-validating a session.
 */
type RefreshTokenPayload = {
    identifier: string;
    version: number;
    jti: string;
    iat?: number;
};
/** Represents a pair of newly issued access and refresh tokens. */
interface TokenPair {
    accessToken: string;
    refreshToken: string;
}
/** The contract for the Data Access Layer, defining database interactions. */
interface UserIdentityDAL<T extends UserIdentity> {
    fetchIdentityByCredentials: (signInIdentifier: string, secret: string) => Promise<T | null>;
    fetchIdentityForSession: (identifier: string) => Promise<T | null>;
    invalidateAllSessionsForIdentity: (identifier: string) => Promise<void>;
    isTokenJtiUsed: (jti: string) => Promise<boolean>;
    markTokenJtiAsUsed: (jti: string, expirationInSeconds: number) => Promise<void>;
    /** Optional: Verify MFA code for the user. */
    verifyMFA?: (identifier: string, code: string) => Promise<boolean>;
}
/** Base interface for cookie options. */
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
/** The specific configuration for cookies used by this library. */
interface AuthCookieConfig extends Partial<CookieOptions> {
    name: string;
    value: string;
    maxAge?: number;
}
interface AuthConfig<T extends UserIdentity> {
    dal: UserIdentityDAL<T>;
    secrets: {
        accessTokenSecret: JWTSecret;
        refreshTokenSecret: JWTSecret;
    };
    cookies: {
        access: {
            name: string;
            maxAge: number;
        };
        refresh: {
            name: string;
            maxAge: number;
        };
    };
    baseUrl: string;
    redirects: {
        unauthenticated: string;
        unauthorized: string;
        forbidden: string;
    };
    jwt?: {
        issuer?: string;
        audience?: string;
        alg?: "HS256" | "RS256";
    };
    debug?: boolean;
    refreshTokenRotationIntervalSeconds?: number;
    /** Optional: Rate limit check for sign-in attempts. Returns true if limited. */
    rateLimit?: (signInIdentifier: string) => Promise<boolean>;
    /** Optional: Custom logger function to replace console logs. */
    logger?: (level: "info" | "warn" | "error", message: string, ...args: any[]) => void;
    /** Optional: Custom error messages. */
    errorMessages?: Partial<Record<"InvalidCredentialsError" | "IdentityForbiddenError" | "NotAuthenticatedError" | "ForbiddenError" | "RateLimitError" | "CsrfError", string>>;
    /** Optional: Providers for social/OAuth sign-in. Maps provider name to a function that returns credentials. */
    providers?: Record<string, (authCode: string) => Promise<{
        signInIdentifier: string;
        secret?: string;
    }>>;
    /** Optional: Enable CSRF protection for actions. */
    csrfEnabled?: boolean;
}
interface ProtectionOptions<T extends UserIdentity, C = unknown> {
    unauthenticatedRedirect?: string;
    unauthorizedRedirect?: string;
    forbiddenRedirect?: string;
    redirectParams?: Record<string, string>;
    authorize?: (identity: PublicUserIdentity<T>, context?: C) => Promise<boolean> | boolean;
    context?: C;
}
interface ActionProtectionOptions<T extends UserIdentity, C = unknown> {
    authorize?: (identity: PublicUserIdentity<T>, context?: C) => Promise<boolean> | boolean;
    context?: C;
}

/**
 * @module @waelhabbaldev/next-jwt-auth/errors
 * This module exports custom error classes used throughout the authentication package.
 */
declare class AuthError extends Error {
    constructor(message: string);
}
declare class InvalidCredentialsError extends AuthError {
    constructor(message?: string);
}
declare class IdentityForbiddenError extends AuthError {
    constructor(message?: string);
}
declare class NotAuthenticatedError extends AuthError {
    constructor(message?: string);
}
declare class ForbiddenError extends AuthError {
    constructor(message?: string);
}
declare class RateLimitError extends AuthError {
    constructor(message?: string);
}
declare class CsrfError extends AuthError {
    constructor(message?: string);
}

export { type AuthConfig as A, type CookieOptions as C, ForbiddenError as F, InvalidCredentialsError as I, type JWTSecret as J, NotAuthenticatedError as N, type PublicUserIdentity as P, type RefreshTokenPayload as R, type TokenPair as T, type UserIdentity as U, type AuthSession as a, type ProtectionOptions as b, type ActionProtectionOptions as c, type UserIdentityDAL as d, type AuthCookieConfig as e, AuthError as f, IdentityForbiddenError as g, RateLimitError as h, CsrfError as i };
