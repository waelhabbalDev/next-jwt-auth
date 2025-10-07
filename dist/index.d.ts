import * as next_server from 'next/server';
import { U as UserIdentity, J as JWTSecret, P as PublicUserIdentity, A as AuthConfig, C as CsrfProvider, a as CsrfInput, b as AuthSession, c as ProtectionOptions, d as ActionProtectionOptions } from './index.client-enfGE1l2.js';
export { g as AuthCookieConfig, h as AuthError, f as CookieOptions, k as CsrfError, F as ForbiddenError, i as IdentityForbiddenError, I as InvalidCredentialsError, N as NotAuthenticatedError, j as RateLimitError, R as RefreshTokenPayload, T as TokenPair, e as UserIdentityDAL } from './index.client-enfGE1l2.js';
import 'react/jsx-runtime';
import 'react';
import 'swr';
import 'crypto';

declare function verifyAccessToken<T extends UserIdentity>(token: string, secret: JWTSecret, jwtOptions?: {
    alg?: string;
}): Promise<{
    payload: PublicUserIdentity<T>;
} | null>;

/**
 * Creates and configures the authentication instance.
 */
declare function createAuth<T extends UserIdentity>(config: AuthConfig<T>): {
    getCsrfToken: () => Promise<string>;
    CsrfProvider: typeof CsrfProvider;
    CsrfInput: typeof CsrfInput;
    getSession: () => Promise<AuthSession<T>>;
    refreshSession: () => Promise<void>;
    signIn: (signInIdentifier: string, secret: string, mfaCode?: string, provider?: string, authCode?: string) => Promise<PublicUserIdentity<T>>;
    signOut: () => Promise<void>;
    createMiddleware: (matcher?: (req: next_server.NextRequest) => boolean) => (req: next_server.NextRequest) => Promise<next_server.NextResponse>;
    protectPage: <C>(options?: ProtectionOptions<T, C> | undefined) => Promise<{
        identity: PublicUserIdentity<T>;
    }>;
    protectAction: <C>(options?: ActionProtectionOptions<T, C> | undefined, formData?: FormData) => Promise<{
        identity: PublicUserIdentity<T>;
    }>;
    protectApi: <C>(options?: ProtectionOptions<T, C> | undefined) => Promise<{
        session: {
            identity: PublicUserIdentity<T>;
        } | null;
        response: next_server.NextResponse | null;
    }>;
    createProtectedAction: <TAction extends (formData: FormData) => Promise<any>>(action: TAction, options?: ActionProtectionOptions<T, unknown> | undefined) => (formData: FormData) => Promise<any>;
};

export { ActionProtectionOptions, AuthConfig, AuthSession, JWTSecret, ProtectionOptions, PublicUserIdentity, UserIdentity, createAuth, verifyAccessToken };
