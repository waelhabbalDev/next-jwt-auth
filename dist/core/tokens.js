"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.issueAccessToken = issueAccessToken;
exports.verifyAccessToken = verifyAccessToken;
exports.issueRefreshToken = issueRefreshToken;
exports.verifyRefreshToken = verifyRefreshToken;
const jose_1 = require("jose");
const uuid_1 = require("uuid");
const getSecretKey = (secret) => new TextEncoder().encode(secret);
async function issueAccessToken(identity, secret, expiresIn, jwtOptions) {
    const { version, isForbidden, ...payload } = identity;
    let jwt = new jose_1.SignJWT(payload)
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt()
        .setSubject(identity.identifier)
        .setExpirationTime(`${expiresIn}s`);
    if (jwtOptions?.issuer)
        jwt = jwt.setIssuer(jwtOptions.issuer);
    if (jwtOptions?.audience)
        jwt = jwt.setAudience(jwtOptions.audience);
    return jwt.sign(getSecretKey(secret));
}
async function verifyAccessToken(token, secret) {
    try {
        const { payload } = await (0, jose_1.jwtVerify)(token, getSecretKey(secret));
        return { payload };
    }
    catch {
        return null;
    }
}
async function issueRefreshToken(identity, secret, expiresIn, jwtOptions) {
    const payload = {
        identifier: identity.identifier,
        version: identity.version,
        jti: (0, uuid_1.v4)(),
    };
    let jwt = new jose_1.SignJWT(payload)
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt()
        .setSubject(identity.identifier)
        .setExpirationTime(`${expiresIn}s`);
    if (jwtOptions?.issuer)
        jwt = jwt.setIssuer(jwtOptions.issuer);
    if (jwtOptions?.audience)
        jwt = jwt.setAudience(jwtOptions.audience);
    return jwt.sign(getSecretKey(secret));
}
async function verifyRefreshToken(token, secret) {
    try {
        const { payload } = await (0, jose_1.jwtVerify)(token, getSecretKey(secret));
        return { payload };
    }
    catch {
        return null;
    }
}
//# sourceMappingURL=tokens.js.map