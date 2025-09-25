import { NextRequest, NextResponse } from 'next/server';
import * as react_jsx_runtime from 'react/jsx-runtime';
import React from 'react';
import { SWRResponse } from 'swr';

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

declare function verifyAccessToken<T extends UserIdentity>(token: string, secret: string): Promise<{
    payload: PublicUserIdentity<T>;
} | null>;

type SignInFunction<T extends UserIdentity> = (signInIdentifier: string, secret: string) => Promise<PublicUserIdentity<T> | null>;
type SignOutFunction = () => Promise<void>;
interface AuthContextType<T extends UserIdentity> {
    session: AuthSession<T> | undefined;
    identity: PublicUserIdentity<T> | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    error: AuthError | Error | null;
    signIn: SignInFunction<T>;
    signOut: SignOutFunction;
    mutate: SWRResponse<AuthSession<T>>["mutate"];
}
declare const AuthContext: React.Context<AuthContextType<any> | null>;
interface AuthProviderProps<T extends UserIdentity> {
    children: React.ReactNode;
    initialSession?: AuthSession<T>;
    sessionFetcher: () => Promise<AuthSession<T>>;
    signInAction: SignInFunction<T>;
    signOutAction: SignOutFunction;
}
declare function AuthProvider<T extends UserIdentity>({ children, initialSession, sessionFetcher, signInAction, signOutAction, }: AuthProviderProps<T>): react_jsx_runtime.JSX.Element;

declare function useAuth<T extends UserIdentity>(): AuthContextType<T>;

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

export { type AuthConfig, AuthContext, type AuthContextType, type AuthCookieConfig, AuthError, AuthProvider, type AuthSession, type CookieOptions, IdentityForbiddenError, InvalidCredentialsError, type PublicUserIdentity, type RefreshTokenPayload, type SignInFunction, type SignOutFunction, type TokenPair, type UserIdentity, type UserIdentityDAL, createAuth, useAuth, verifyAccessToken };
