"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getClearRefreshCookie = exports.getClearAccessCookie = exports.getRefreshCookie = exports.getAccessCookie = void 0;
const isProduction = process.env.NODE_ENV === "production";
const baseCookieConfig = {
    httpOnly: true,
    secure: isProduction,
    sameSite: "strict",
    path: "/",
};
const getAccessCookie = (token, name, maxAge) => ({
    name,
    value: token,
    ...baseCookieConfig,
    maxAge,
});
exports.getAccessCookie = getAccessCookie;
const getRefreshCookie = (token, name, maxAge) => ({
    name,
    value: token,
    ...baseCookieConfig,
    maxAge,
});
exports.getRefreshCookie = getRefreshCookie;
const getClearAccessCookie = (name) => ({
    name,
    value: "",
    ...baseCookieConfig,
    maxAge: -1,
});
exports.getClearAccessCookie = getClearAccessCookie;
const getClearRefreshCookie = (name) => ({
    name,
    value: "",
    ...baseCookieConfig,
    maxAge: -1,
});
exports.getClearRefreshCookie = getClearRefreshCookie;
//# sourceMappingURL=cookies.js.map