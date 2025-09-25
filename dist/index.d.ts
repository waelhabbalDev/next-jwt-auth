import { NextRequest, NextResponse } from "next/server";
import { UserIdentity, UserIdentityDAL, AuthSession } from "./types";
export * from "./types";
export * from "./core/errors";
export { verifyAccessToken } from "./core/tokens";
export { AuthProvider } from "./client/provider";
export { useAuth } from "./client/use-auth";
export interface AuthConfig<T extends UserIdentity> {
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
export declare function createAuth<T extends UserIdentity>(config: AuthConfig<T>): {
    getAuthSession: (req?: NextRequest) => Promise<AuthSession<T>>;
    signIn: (loginIdentifier: string, secret: string) => Promise<import("./types").PublicUserIdentity<T>>;
    signOut: () => Promise<void>;
    createAuthMiddleware: (matcher?: (req: NextRequest) => boolean) => (req: NextRequest) => Promise<NextResponse<unknown>>;
};
