interface UserIdentity {
    identifier: string;
    roles: string[];
    version: number;
    isForbidden: boolean;
    hasMFA?: boolean;
}
type PublicUserIdentity<T extends UserIdentity> = Omit<T, "version" | "isForbidden">;
type AuthSession<T extends UserIdentity> = {
    identity: PublicUserIdentity<T>;
} | null;
/**
 * Represents the secret used for signing and verifying JWTs.
 * Removed `KeyObject` from the public type to ensure Edge Runtime compatibility.
 * Users should pass PEM-encoded strings for asymmetric keys.
 */
type JWTSecret = string | {
    key: string;
    kid?: string;
} | {
    key: string;
    kid?: string;
}[];
type RefreshTokenPayload = {
    identifier: string;
    version: number;
    jti: string;
    iat?: number;
};
interface TokenPair {
    accessToken: string;
    refreshToken: string;
}
interface UserIdentityDAL<T extends UserIdentity> {
    fetchIdentityByCredentials: (signInIdentifier: string, secret: string) => Promise<T | null>;
    fetchIdentityForSession: (identifier: string) => Promise<T | null>;
    invalidateAllSessionsForIdentity: (identifier: string) => Promise<void>;
    isTokenJtiUsed: (jti: string) => Promise<boolean>;
    markTokenJtiAsUsed: (jti: string, expirationInSeconds: number) => Promise<void>;
    verifyMFA?: (identifier: string, code: string) => Promise<boolean>;
}
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
    rateLimit?: (signInIdentifier: string) => Promise<boolean>;
    logger?: (level: "info" | "warn" | "error", message: string, ...args: any[]) => void;
    errorMessages?: Partial<Record<"InvalidCredentialsError" | "IdentityForbiddenError" | "NotAuthenticatedError" | "ForbiddenError" | "RateLimitError" | "CsrfError", string>>;
    providers?: Record<string, (authCode: string) => Promise<{
        signInIdentifier: string;
        secret?: string;
    }>>;
    csrfEnabled?: boolean;
}
/**
 * Protection options are now context-aware for advanced authorization.
 * The `authorize` function now receives a single object with both `identity` and `context`.
 */
interface ProtectionOptions<T extends UserIdentity, C = unknown> {
    unauthenticatedRedirect?: string;
    unauthorizedRedirect?: string;
    forbiddenRedirect?: string;
    redirectParams?: Record<string, string>;
    authorize?: (params: {
        identity: PublicUserIdentity<T>;
        context: C;
    }) => Promise<boolean> | boolean;
    context: C;
}
/**
 *  Action protection options are also now context-aware.
 */
interface ActionProtectionOptions<T extends UserIdentity, C = unknown> {
    authorize?: (params: {
        identity: PublicUserIdentity<T>;
        context: C;
    }) => Promise<boolean> | boolean;
    context: C;
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
