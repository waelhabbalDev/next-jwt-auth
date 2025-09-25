import { NextRequest } from "next/server";
import { AuthConfig } from "../index";
import { UserIdentity, AuthSession, PublicUserIdentity } from "../types";
export declare function signIn<T extends UserIdentity>(loginIdentifier: string, secret: string, config: AuthConfig<T>): Promise<PublicUserIdentity<T>>;
export declare function signOut<T extends UserIdentity>(config: AuthConfig<T>): Promise<void>;
type GetSessionResult<T extends UserIdentity> = {
    session: AuthSession<T>;
    newTokens?: {
        accessToken: string;
        refreshToken?: string;
    } | null;
};
export declare function getAuthSession<T extends UserIdentity>(config: AuthConfig<T>, req?: NextRequest): Promise<GetSessionResult<T>>;
export {};
