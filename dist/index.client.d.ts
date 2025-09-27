import * as react_jsx_runtime from 'react/jsx-runtime';
import React from 'react';
import { SWRResponse } from 'swr';
import { U as UserIdentity, P as PublicUserIdentity, A as AuthSession, c as AuthError } from './errors-CqxeYHdU.js';

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

export { AuthContext, type AuthContextType, AuthProvider, type SignInFunction, type SignOutFunction, useAuth };
