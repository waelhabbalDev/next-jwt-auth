"use strict";
"use client";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthContext = void 0;
exports.AuthProvider = AuthProvider;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const swr_1 = __importDefault(require("swr"));
exports.AuthContext = (0, react_1.createContext)(null);
function AuthProvider({ children, initialSession, sessionFetcher, signInAction, signOutAction, }) {
    const { data: session, isLoading, mutate, } = (0, swr_1.default)("auth-session-key", sessionFetcher, {
        fallbackData: initialSession,
        revalidateOnFocus: true,
        revalidateOnReconnect: true,
        shouldRetryOnError: false,
    });
    const handleSignIn = (0, react_1.useCallback)(async (signInIdentifier, secret) => {
        try {
            const identity = await signInAction(signInIdentifier, secret);
            await mutate();
            return identity;
        }
        catch {
            return null;
        }
    }, [signInAction, mutate]);
    const handleSignOut = (0, react_1.useCallback)(async () => {
        await signOutAction();
        await mutate(null, { revalidate: true });
    }, [signOutAction, mutate]);
    const contextValue = (0, react_1.useMemo)(() => ({
        session,
        identity: session?.identity ?? null,
        isAuthenticated: !!session?.identity,
        isLoading,
        signIn: handleSignIn,
        signOut: handleSignOut,
        mutate,
    }), [session, isLoading, handleSignIn, handleSignOut, mutate]);
    return ((0, jsx_runtime_1.jsx)(exports.AuthContext.Provider, { value: contextValue, children: children }));
}
//# sourceMappingURL=provider.js.map