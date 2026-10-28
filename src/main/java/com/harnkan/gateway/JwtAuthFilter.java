package com.harnkan.gateway;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import reactor.core.publisher.Mono;

@Component
public class JwtAuthFilter implements WebFilter, Ordered {

    public static final String HEADER_USER_ID = "X-User-Id";
    public static final String HEADER_USER_NAME = "X-User-Name";
    public static final String TOKEN_COOKIE = "token";

    private static final String BEARER = "Bearer ";

    private final ReactiveJwtDecoder jwtDecoder;
    private final ObjectMapper objectMapper;

    public JwtAuthFilter(ReactiveJwtDecoder jwtDecoder, ObjectMapper objectMapper) {
        this.jwtDecoder = jwtDecoder;
        this.objectMapper = objectMapper;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (isInternal(path)) {
            return error(exchange, HttpStatus.NOT_FOUND, "NOT_FOUND", "No such route");
        }

        ServerWebExchange stripped = exchange.mutate()
                .request(r -> r.headers(h -> {
                    h.remove(HEADER_USER_ID);
                    h.remove(HEADER_USER_NAME);
                }))
                .build();

        if (isPublic(path)) {
            return chain.filter(stripped);
        }

        String token = extractToken(stripped);
        if (token == null) {
            return error(stripped, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Missing token");
        }
        return jwtDecoder.decode(token)
                .onErrorMap(JwtException.class, JwtRejected::new)
                .flatMap(jwt -> chain.filter(withUser(stripped, jwt)))
                .onErrorResume(JwtRejected.class, e -> error(stripped, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Invalid or expired token"));
    }

    private static ServerWebExchange withUser(ServerWebExchange exchange, Jwt jwt) {
        String name = jwt.getClaimAsString("name");
        return exchange.mutate()
                .request(r -> r.headers(h -> {
                    h.set(HEADER_USER_ID, jwt.getSubject());
                    if (name != null && !name.isBlank()) {
                        h.set(HEADER_USER_NAME, UriUtils.encode(name.trim(), StandardCharsets.UTF_8));
                    }
                }))
                .build();
    }

    static boolean isInternal(String path) {
        return path.equals("/internal") || path.startsWith("/internal/");
    }

    static boolean isPublic(String path) {
        return path.equals("/api/auth") || path.startsWith("/api/auth/")
                || path.equals("/webhooks/stripe")
                || path.equals("/actuator/health") || path.startsWith("/actuator/health/");
    }

    private static String extractToken(ServerWebExchange exchange) {
        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.regionMatches(true, 0, BEARER, 0, BEARER.length())) {
            String token = authorization.substring(BEARER.length()).trim();
            if (!token.isEmpty()) {
                return token;
            }
        }
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst(TOKEN_COOKIE);
        return cookie == null || cookie.getValue().isBlank() ? null : cookie.getValue();
    }

    /** {code, message, timestamp}: the error shape every service uses. */
    private Mono<Void> error(ServerWebExchange exchange, HttpStatus status, String code, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", code);
        body.put("message", message);
        body.put("timestamp", Instant.now().toString());
        byte[] bytes;
        try {
            bytes = objectMapper.writeValueAsBytes(body);
        } catch (JsonProcessingException e) {
            bytes = ("{\"code\":\"" + code + "\"}").getBytes(StandardCharsets.UTF_8);
        }
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    /** Marker so only decode failures (not downstream errors) are answered with 401. */
    private static final class JwtRejected extends RuntimeException {
        JwtRejected(Throwable cause) {
            super(cause);
        }
    }
}
