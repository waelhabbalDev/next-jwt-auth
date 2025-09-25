import React from "react";
import { SWRResponse } from "swr";
import { AuthSession, UserIdentity, PublicUserIdentity } from "../types";
import { AuthError } from "../core/errors";
export type SignInFunction<T extends UserIdentity> = (signInIdentifier: string, secret: string) => Promise<PublicUserIdentity<T> | null>;
export type SignOutFunction = () => Promise<void>;
export interface AuthContextType<T extends UserIdentity> {
    session: AuthSession<T> | undefined;
    identity: PublicUserIdentity<T> | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    error: AuthError | Error | null;
    signIn: SignInFunction<T>;
    signOut: SignOutFunction;
    mutate: SWRResponse<AuthSession<T>>["mutate"];
}
export declare const AuthContext: React.Context<AuthContextType<any> | null>;
interface AuthProviderProps<T extends UserIdentity> {
    children: React.ReactNode;
    initialSession?: AuthSession<T>;
    sessionFetcher: () => Promise<AuthSession<T>>;
    signInAction: SignInFunction<T>;
    signOutAction: SignOutFunction;
}
export declare function AuthProvider<T extends UserIdentity>({ children, initialSession, sessionFetcher, signInAction, signOutAction, }: AuthProviderProps<T>): import("react/jsx-runtime").JSX.Element;
export {};
