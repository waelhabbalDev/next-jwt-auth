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

declare class AuthError extends Error {
    constructor(message: string);
}
declare class InvalidCredentialsError extends AuthError {
    constructor();
}
declare class IdentityForbiddenError extends AuthError {
    constructor();
}

export { type AuthSession as A, type CookieOptions as C, InvalidCredentialsError as I, type PublicUserIdentity as P, type RefreshTokenPayload as R, type TokenPair as T, type UserIdentity as U, type UserIdentityDAL as a, type AuthCookieConfig as b, AuthError as c, IdentityForbiddenError as d };
