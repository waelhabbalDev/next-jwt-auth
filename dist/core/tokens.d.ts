import { UserIdentity, PublicUserIdentity, RefreshTokenPayload } from "../types";
export declare function issueAccessToken<T extends UserIdentity>(identity: T, secret: string, expiresIn: number, jwtOptions?: {
    issuer?: string;
    audience?: string;
}): Promise<string>;
export declare function verifyAccessToken<T extends UserIdentity>(token: string, secret: string): Promise<{
    payload: PublicUserIdentity<T>;
} | null>;
export declare function issueRefreshToken<T extends UserIdentity>(identity: T, secret: string, expiresIn: number, jwtOptions?: {
    issuer?: string;
    audience?: string;
}): Promise<string>;
export declare function verifyRefreshToken(token: string, secret: string): Promise<{
    payload: RefreshTokenPayload;
} | null>;
