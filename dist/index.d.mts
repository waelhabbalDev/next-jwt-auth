import * as next_server from 'next/server';
import { U as UserIdentity, J as JWTSecret, P as PublicUserIdentity, A as AuthConfig, a as AuthSession, b as ProtectionOptions, c as ActionProtectionOptions } from './errors-CoGEeF97.mjs';
export { e as AuthCookieConfig, f as AuthError, C as CookieOptions, i as CsrfError, F as ForbiddenError, g as IdentityForbiddenError, I as InvalidCredentialsError, N as NotAuthenticatedError, h as RateLimitError, R as RefreshTokenPayload, T as TokenPair, d as UserIdentityDAL } from './errors-CoGEeF97.mjs';
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
    getSession: () => Promise<AuthSession<T>>;
    refreshSession: () => Promise<void>;
    signIn: (signInIdentifier: string, secret: string, mfaCode?: string, provider?: string, authCode?: string) => Promise<PublicUserIdentity<T>>;
    signOut: () => Promise<void>;
    createMiddleware: (matcher?: (req: next_server.NextRequest) => boolean) => (req: next_server.NextRequest) => Promise<next_server.NextResponse>;
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

export { ActionProtectionOptions, AuthConfig, AuthSession, JWTSecret, ProtectionOptions, PublicUserIdentity, UserIdentity, createAuth, verifyAccessToken };
