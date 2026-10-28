package com.harnkan.gateway;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/** Makes HS256 tokens the way User Service does. */
final class TestTokens {

    static final String SECRET = "unit-test-secret-unit-test-secret-0123456789";

    private TestTokens() {
    }

    static String token(String secret, String sub, String name, Date expiresAt) {
        try {
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().expirationTime(expiresAt);
            if (sub != null) {
                claims.subject(sub).claim("id", sub);
            }
            if (name != null) {
                claims.claim("name", name);
            }
            SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims.build());
            jwt.sign(new MACSigner(secret.getBytes(StandardCharsets.UTF_8)));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    static String valid(String sub, String name) {
        return token(SECRET, sub, name, new Date(System.currentTimeMillis() + 60_000));
    }
}
