import * as next_server from 'next/server';
import { NextRequest } from 'next/server';
import { U as UserIdentity, P as PublicUserIdentity, a as UserIdentityDAL, A as AuthSession } from './errors-CqxeYHdU.mjs';
export { b as AuthCookieConfig, c as AuthError, C as CookieOptions, F as ForbiddenError, d as IdentityForbiddenError, I as InvalidCredentialsError, N as NotAuthenticatedError, R as RefreshTokenPayload, T as TokenPair } from './errors-CqxeYHdU.mjs';

declare function verifyAccessToken<T extends UserIdentity>(token: string, secret: string): Promise<{
    payload: PublicUserIdentity<T>;
} | null>;

interface AuthConfig<T extends UserIdentity> {
    dal: UserIdentityDAL<T>;
    secrets: {
        accessTokenSecret: string;
        refreshTokenSecret: string;
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
    };
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
 * Creates and configures the authentication instance.
 * This is the main function to initialize the package.
 * @param config The configuration object for the authentication system.
 * @returns An object containing authentication methods and protection guards.
 */
declare function createAuth<T extends UserIdentity>(config: AuthConfig<T>): {
    getSession: () => Promise<AuthSession<T>>;
    signIn: (signInIdentifier: string, secret: string) => Promise<PublicUserIdentity<T>>;
    signOut: () => Promise<void>;
    createMiddleware: (matcher?: (req: NextRequest) => boolean) => (req: NextRequest) => Promise<next_server.NextResponse>;
    protectPage: <C>(options?: ProtectionOptions<T, C> | undefined) => Promise<{
        identity: PublicUserIdentity<T>;
    }>;
    protectAction: <C>(options?: ActionProtectionOptions<T, C> | undefined) => Promise<{
        identity: PublicUserIdentity<T>;
    }>;
    protectApi: <C>(options?: ProtectionOptions<T, C> | undefined) => Promise<{
        session: {
            identity: PublicUserIdentity<T>;
        } | null;
        response: next_server.NextResponse | null;
    }>;
};

export { type ActionProtectionOptions, type AuthConfig, AuthSession, type ProtectionOptions, PublicUserIdentity, UserIdentity, UserIdentityDAL, createAuth, verifyAccessToken };
