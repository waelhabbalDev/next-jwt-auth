import { NextRequest, NextResponse } from 'next/server';
import { U as UserIdentity, J as JWTSecret, P as PublicUserIdentity, A as AuthConfig, a as AuthSession, b as ProtectionOptions, c as ActionProtectionOptions } from './errors-Cs5AALcF.mjs';
export { e as AuthCookieConfig, f as AuthError, C as CookieOptions, i as CsrfError, F as ForbiddenError, g as IdentityForbiddenError, I as InvalidCredentialsError, N as NotAuthenticatedError, h as RateLimitError, R as RefreshTokenPayload, T as TokenPair, d as UserIdentityDAL } from './errors-Cs5AALcF.mjs';

declare function verifyAccessToken<T extends UserIdentity>(token: string, secret: JWTSecret, jwtOptions?: {
    alg?: string;
}): Promise<{
    payload: PublicUserIdentity<T>;
} | null>;

/**
 * Creates and configures the authentication instance for the Next.js App Router.
 */
declare function createAuth<T extends UserIdentity>(config: AuthConfig<T>): {
    getSession: () => Promise<AuthSession<T>>;
    createMiddleware: (matcher?: (req: NextRequest) => boolean) => (req: NextRequest) => Promise<NextResponse<unknown>>;
    signIn: (signInIdentifier: string, secret: string, mfaCode?: string, provider?: string, authCode?: string) => Promise<PublicUserIdentity<T>>;
    signOut: () => Promise<void>;
    getCsrfToken: () => Promise<string>;
    protectPage: <C>(options?: ProtectionOptions<T, C>) => Promise<NonNullable<AuthSession<T>>>;
    protectAction: <C>(options?: ActionProtectionOptions<T, C>, formData?: FormData) => Promise<NonNullable<AuthSession<T>>>;
    protectApi: <C>(options?: ProtectionOptions<T, C>) => Promise<{
        session: NonNullable<AuthSession<T>>;
    } | {
        response: NextResponse;
    }>;
};

export { ActionProtectionOptions, AuthConfig, AuthSession, JWTSecret, ProtectionOptions, PublicUserIdentity, UserIdentity, createAuth, verifyAccessToken };
