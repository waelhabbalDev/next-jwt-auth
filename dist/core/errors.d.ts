export declare class AuthError extends Error {
    constructor(message: string);
}
export declare class InvalidCredentialsError extends AuthError {
    constructor();
}
export declare class IdentityForbiddenError extends AuthError {
    constructor();
}
