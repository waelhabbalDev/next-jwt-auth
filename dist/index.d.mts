import { U as UserIdentity, P as PublicUserIdentity, a as UserIdentityDAL, A as AuthSession } from './errors-kpDWGww1.mjs';
export { b as AuthCookieConfig, c as AuthError, C as CookieOptions, d as IdentityForbiddenError, I as InvalidCredentialsError, R as RefreshTokenPayload, T as TokenPair } from './errors-kpDWGww1.mjs';
import { NextRequest, NextResponse } from 'next/server';

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
    jwt?: {
        issuer?: string;
        audience?: string;
    };
    rotationStrategy?: "always" | "on-demand";
}
declare function createAuth<T extends UserIdentity>(config: AuthConfig<T>): {
    getAuthSession: () => Promise<AuthSession<T>>;
    signIn: (signInIdentifier: string, secret: string) => Promise<PublicUserIdentity<T>>;
    signOut: () => Promise<void>;
    createAuthMiddleware: (matcher?: (req: NextRequest) => boolean) => (req: NextRequest) => Promise<NextResponse<unknown>>;
};

export { type AuthConfig, AuthSession, PublicUserIdentity, UserIdentity, UserIdentityDAL, createAuth, verifyAccessToken };
