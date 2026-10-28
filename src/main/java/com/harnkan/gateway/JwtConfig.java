package com.harnkan.gateway;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

@Configuration
public class JwtConfig {

    private static final int MIN_SECRET_LENGTH = 32;

    @Bean
    ReactiveJwtDecoder jwtDecoder(@Value("${gateway.jwt-secret:}") String secret) {
        byte[] key = secret.getBytes(StandardCharsets.UTF_8);
        if (key.length < MIN_SECRET_LENGTH) {
            throw new IllegalStateException(
                    "JWT_SECRET (gateway.jwt-secret) must be set and at least " + MIN_SECRET_LENGTH + " characters");
        }
        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder
                .withSecretKey(new SecretKeySpec(key, "HmacSHA256"))
                .macAlgorithm(MacAlgorithm.HS256)
                .build();

        OAuth2TokenValidator<Jwt> timestamps = new JwtTimestampValidator(Duration.ZERO);
        decoder.setJwtValidator(jwt -> {
            OAuth2TokenValidatorResult result = timestamps.validate(jwt);
            if (result.hasErrors()) {
                return result;
            }
            if (jwt.getExpiresAt() == null || !(jwt.getClaims().get("sub") instanceof String sub) || sub.isBlank()) {
                return OAuth2TokenValidatorResult.failure(
                        new OAuth2Error("invalid_token", "JWT must have exp and a string sub", null));
            }
            return OAuth2TokenValidatorResult.success();
        });
        return decoder;
    }
}
