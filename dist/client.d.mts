import * as react_jsx_runtime from 'react/jsx-runtime';
import React from 'react';
import { SWRResponse } from 'swr';
import { U as UserIdentity, P as PublicUserIdentity, a as AuthSession, f as AuthError } from './errors-Cs5AALcF.mjs';

/**
 * A provider component that makes a server-provided CSRF token available to its children.
 * This is the primary and most performant way to handle CSRF.
 */
declare function CsrfProvider({ token, children, }: {
    token: string;
    children: React.ReactNode;
}): react_jsx_runtime.JSX.Element;
/**
 * A client-side hook to programmatically access the CSRF token from the provider.
 */
declare function useCsrf(): string | null;
/**
 * A simple CSRF input that gets its value from the CsrfProvider context.
 * It no longer performs its own data fetching, making it faster.
 */
declare function CsrfInput(): react_jsx_runtime.JSX.Element | null;
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
    /**
     * The SWR mutate function to programmatically revalidate the session.
     * Replaces the manual `refresh` function for a more powerful API.
     */
    mutate: SWRResponse<AuthSession<T>>["mutate"];
}
declare const AuthContext: React.Context<AuthContextType<any> | null>;
interface AuthProviderProps<T extends UserIdentity> {
    children: React.ReactNode;
    /**
     * The initial session, fetched on the server and passed to the client.
     * This is crucial for avoiding a client-side fetch on initial page load.
     */
    initialSession?: AuthSession<T>;
    /** A Server Action that returns the current session. */
    sessionFetcher: () => Promise<AuthSession<T>>;
    /** A Server Action for signing in. */
    signInAction: SignInFunction<T>;
    /** A Server Action for signing out. */
    signOutAction: SignOutFunction;
}
declare function AuthProvider<T extends UserIdentity>({ children, initialSession, sessionFetcher, signInAction, signOutAction, }: AuthProviderProps<T>): react_jsx_runtime.JSX.Element;
/**
 * The primary hook for accessing authentication state in Client Components.
 */
declare function useAuth<T extends UserIdentity>(): AuthContextType<T>;

export { AuthContext, type AuthContextType, AuthProvider, CsrfInput, CsrfProvider, type SignInFunction, type SignOutFunction, useAuth, useCsrf };
