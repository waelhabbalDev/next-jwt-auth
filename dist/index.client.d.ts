import * as react_jsx_runtime from 'react/jsx-runtime';
import React from 'react';
import { SWRResponse } from 'swr';
import { U as UserIdentity, P as PublicUserIdentity, a as AuthSession, f as AuthError } from './errors-CoGEeF97.js';
import 'crypto';

/**
 * A provider component that makes the CSRF token available to its children.
 * This should be used in a Server Component to wrap the Client Component containing the form.
 * @param {object} props - The component props.
 * @param {string} props.token - The CSRF token.
 * @param {React.ReactNode} props.children - The child components.
 */
declare function CsrfProvider({ token, children, }: {
    token: string;
    children: React.ReactNode;
}): react_jsx_runtime.JSX.Element;
/**
 * A client-side hook to programmatically access the CSRF token.
 * This is useful for making manual fetch requests or for use with libraries
 * that don't use standard <form> elements.
 * The component must be a child of a <CsrfProvider>.
 */
declare function useCsrf(): string | null;
/**
 * A "smart" CSRF input component that uses SWR for efficient, cached token fetching.
 *
 * @param {object} props - The component props.
 * @param {() => Promise<string>} [props.getTokenAction] - A Server Action to fetch the CSRF token.
 */
declare function CsrfInput({ getTokenAction, }: {
    getTokenAction?: () => Promise<string>;
}): react_jsx_runtime.JSX.Element | null;
type SignInFunction<T extends UserIdentity> = (signInIdentifier: string, secret: string, mfaCode?: string, provider?: string, authCode?: string) => Promise<PublicUserIdentity<T> | null>;
type SignOutFunction = () => Promise<void>;
interface AuthContextType<T extends UserIdentity> {
    session: AuthSession<T> | undefined;
    identity: PublicUserIdentity<T> | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    error: AuthError | Error | null;
    signIn: SignInFunction<T>;
    signOut: SignOutFunction;
    refresh: () => Promise<void>;
    mutate: SWRResponse<AuthSession<T>>["mutate"];
}
declare const AuthContext: React.Context<AuthContextType<any> | null>;
interface AuthProviderProps<T extends UserIdentity> {
    children: React.ReactNode;
    initialSession?: AuthSession<T>;
    sessionFetcher: () => Promise<AuthSession<T>>;
    signInAction: SignInFunction<T>;
    signOutAction: SignOutFunction;
    refreshAction: () => Promise<void>;
}
declare function AuthProvider<T extends UserIdentity>({ children, initialSession, sessionFetcher, signInAction, signOutAction, refreshAction, }: AuthProviderProps<T>): react_jsx_runtime.JSX.Element;
declare function useAuth<T extends UserIdentity>(): AuthContextType<T>;

export { AuthContext, type AuthContextType, AuthProvider, CsrfInput, CsrfProvider, type SignInFunction, type SignOutFunction, useAuth, useCsrf };
