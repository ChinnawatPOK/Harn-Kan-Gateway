# Harn Kan API Gateway

Spring Cloud Gateway (WebFlux). The single entry point for the mobile app: it verifies the JWT once, then routes to the services with static routes (see `application.yaml`).

| Public path | Service | Token |
|---|---|---|
| `/api/auth/**` → `/api/v1/auth/**` | user-service (3000) | not needed |
| `/api/users/**` → `/api/v1/users/**` | user-service (3000) | required |
| `/api/deals/**` | deal-service (8081) | required |
| `/api/payments/**` | payment-service (8082) | required |
| `/api/notifications/**` | notification-service (3002) | required |
| `/webhooks/stripe` | payment-service (8082) | not needed (Payment checks Stripe's signature) |
| `/internal/**` | – | always 404 |

`JwtAuthFilter` does the work: HS256 check with `JWT_SECRET`, token from `Authorization: Bearer` then cookie `token`, drops any client-sent `X-User-*`, then sets `X-User-Id` (= `sub`) and `X-User-Name` (= claim `name`, percent-encoded UTF-8). Errors are `{code, message, timestamp}`.

## Run

```bash
export JWT_SECRET=...   # the secret User Service signs with, >= 32 chars (never commit it)
mvn spring-boot:run
```

Service locations can be overridden with `USER_SERVICE_URL`, `DEAL_SERVICE_URL`, `PAYMENT_SERVICE_URL`, `NOTIFICATION_SERVICE_URL`. With Docker: copy `.env.example` to `.env`, then `docker compose up --build`.

## Test

`mvn test` starts the real gateway against a recording mock server standing in for every service.
