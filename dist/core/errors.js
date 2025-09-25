"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IdentityForbiddenError = exports.InvalidCredentialsError = exports.AuthError = void 0;
class AuthError extends Error {
    constructor(message) {
        super(message);
        this.name = "AuthError";
    }
}
exports.AuthError = AuthError;
class InvalidCredentialsError extends AuthError {
    constructor() {
        super("Invalid credentials provided.");
        this.name = "InvalidCredentialsError";
    }
}
exports.InvalidCredentialsError = InvalidCredentialsError;
class IdentityForbiddenError extends AuthError {
    constructor() {
        super("This identity is forbidden from logging in.");
        this.name = "IdentityForbiddenError";
    }
}
exports.IdentityForbiddenError = IdentityForbiddenError;
//# sourceMappingURL=errors.js.map