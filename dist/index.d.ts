import { NextRequest, NextResponse } from 'next/server';
import { U as UserIdentity, P as PublicUserIdentity, a as UserIdentityDAL, A as AuthSession } from './errors-CqxeYHdU.js';
export { b as AuthCookieConfig, c as AuthError, C as CookieOptions, F as ForbiddenError, d as IdentityForbiddenError, I as InvalidCredentialsError, N as NotAuthenticatedError, R as RefreshTokenPayload, T as TokenPair } from './errors-CqxeYHdU.js';

declare function verifyAccessToken<T extends UserIdentity>(token: string, secret: string): Promise<{
    payload: PublicUserIdentity<T>;
} | null>;

/**
 * @module @waelhabbaldev/next-jwt-auth/server
 * This is the main server-side entry point for the authentication package.
 * It exports the `createAuth` function which initializes the authentication system,
 * along with all necessary types and error classes for server-side use.
 */

/**
 * Configuration object for the createAuth function.
 */
interface AuthConfig<T extends UserIdentity> {
    /** Data Access Layer for user identity operations. */
    dal: UserIdentityDAL<T>;
    /** Cryptographic secrets for signing tokens. Must be at least 32 characters long. */
    secrets: {
        accessTokenSecret: string;
        refreshTokenSecret: string;
    };
    /** Configuration for the authentication cookies. */
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
    /** The fully-qualified base URL of your application (e.g., "https://yourapp.com"). */
    baseUrl: string;
    /** Paths to redirect to for different authorization states. */
    redirects: {
        /** Path for users who are not logged in. */
        unauthenticated: string;
        /** Path for authenticated users who lack specific permissions for a resource. */
        unauthorized: string;
        /** Path for users whose accounts are globally forbidden or suspended. */
        forbidden: string;
    };
    /** Optional settings for JWT claims. */
    jwt?: {
        issuer?: string;
        audience?: string;
    };
}
/**
 * Options for the `protectPage` and `protectApi` guards to control authorization and redirect behavior.
 */
interface ProtectionOptions<T extends UserIdentity, C = unknown> {
    /** Override the default redirect path for unauthenticated users. */
    unauthenticatedRedirect?: string;
    /** Override the default redirect path for unauthorized (forbidden) users. */
    unauthorizedRedirect?: string;
    /** Override the default redirect path for globally forbidden users. */
    forbiddenRedirect?: string;
    /** A key-value object to add as search parameters to the redirect URL on failure. */
    redirectParams?: Record<string, string>;
    /**
     * Authorization logic to check roles or claims.
     * @param identity The authenticated user's identity.
     * @param context Optional context for complex checks (e.g., resource ownership).
     * @returns {Promise<boolean> | boolean} True if authorized, false otherwise.
     */
    authorize?: (identity: PublicUserIdentity<T>, context?: C) => Promise<boolean> | boolean;
    /** Optional context to be passed to the `authorize` function. */
    context?: C;
}
/**
 * Options for the `protectAction` guard to control authorization.
 */
interface ActionProtectionOptions<T extends UserIdentity, C = unknown> {
    /**
     * Authorization logic to check roles or claims.
     * @param identity The authenticated user's identity.
     * @param context Optional context for complex checks (e.g., resource ownership).
     * @returns {Promise<boolean> | boolean} True if authorized, false otherwise.
     */
    authorize?: (identity: PublicUserIdentity<T>, context?: C) => Promise<boolean> | boolean;
    /** Optional context to be passed to the `authorize` function. */
    context?: C;
}
/**
 * Creates and configures the authentication instance.
 * This is the main function to initialize the package.
 * @param config The configuration object for the authentication system.
 * @returns An object containing authentication methods and protection guards for use in a Next.js application.
 */
declare function createAuth<T extends UserIdentity>(config: AuthConfig<T>): {
    getAuthSession: () => Promise<AuthSession<T>>;
    signIn: (signInIdentifier: string, secret: string) => Promise<PublicUserIdentity<T>>;
    signOut: () => Promise<void>;
    createAuthMiddleware: (matcher?: (req: NextRequest) => boolean) => Function;
    protectPage: <C>(options?: ProtectionOptions<T, C>) => Promise<NonNullable<AuthSession<T>>>;
    protectAction: <C>(options?: ActionProtectionOptions<T, C>) => Promise<NonNullable<AuthSession<T>>>;
    protectApi: <C>(options?: ProtectionOptions<T, C>) => Promise<{
        session: NonNullable<AuthSession<T>>;
        response?: never;
    } | {
        session?: never;
        response: NextResponse;
    }>;
};

export { type ActionProtectionOptions, type AuthConfig, AuthSession, type ProtectionOptions, PublicUserIdentity, UserIdentity, UserIdentityDAL, createAuth, verifyAccessToken };
