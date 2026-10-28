package com.harnkan.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

/**
 * Real gateway on a random port, every service replaced by one recording MockWebServer:
 * checks what actually reaches the service (path, user headers) and what the client gets back.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GatewayRoutingTest {

    static final MockWebServer downstream = new MockWebServer();

    @BeforeAll
    static void start() throws Exception {
        downstream.start();
    }

    @AfterAll
    static void stop() throws Exception {
        downstream.shutdown();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        String url = "http://localhost:" + downstream.getPort();
        registry.add("gateway.jwt-secret", () -> TestTokens.SECRET);
        registry.add("USER_SERVICE_URL", () -> url);
        registry.add("DEAL_SERVICE_URL", () -> url);
        registry.add("PAYMENT_SERVICE_URL", () -> url);
        registry.add("NOTIFICATION_SERVICE_URL", () -> url);
    }

    @LocalServerPort
    int port;

    @Autowired
    WebTestClient client;

    private WebTestClient gateway() {
        return WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
    }

    private RecordedRequest forwarded() throws InterruptedException {
        RecordedRequest request = downstream.takeRequest(2, TimeUnit.SECONDS);
        assertThat(request).as("request reached the service").isNotNull();
        return request;
    }

    private static void respondOk() {
        downstream.enqueue(new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody("{}"));
    }

    @Test
    void deals_withValidToken_setsUserHeadersAndKeepsPath() throws Exception {
        respondOk();

        gateway().get().uri("/api/deals/nearby?lat=13.7&lng=100.5")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestTokens.valid("6aa12c60a64bc2e2be695ec1", "Ploy S."))
                .exchange().expectStatus().isOk();

        RecordedRequest request = forwarded();
        assertThat(request.getPath()).isEqualTo("/api/deals/nearby?lat=13.7&lng=100.5");
        assertThat(request.getHeader("X-User-Id")).isEqualTo("6aa12c60a64bc2e2be695ec1");
        assertThat(request.getHeader("X-User-Name")).isEqualTo("Ploy%20S.");
    }

    @Test
    void thaiNameSurvivesAsPercentEncodedHeader() throws Exception {
        respondOk();

        gateway().get().uri("/api/deals/d1")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestTokens.valid("u1", "พลอย ส."))
                .exchange().expectStatus().isOk();

        String header = forwarded().getHeader("X-User-Name");
        assertThat(java.net.URLDecoder.decode(header.replace("+", "%2B"), java.nio.charset.StandardCharsets.UTF_8))
                .isEqualTo("พลอย ส.");
    }

    @Test
    void forgedUserHeadersAreReplacedByTheTokenOnes() throws Exception {
        respondOk();

        gateway().get().uri("/api/deals/d1")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestTokens.valid("real-user", "Real R."))
                .header("X-User-Id", "admin").header("X-User-Name", "Evil")
                .exchange().expectStatus().isOk();

        RecordedRequest request = forwarded();
        assertThat(request.getHeaders().values("X-User-Id")).containsExactly("real-user");
        assertThat(request.getHeader("X-User-Name")).isEqualTo("Real%20R.");
    }

    @Test
    void forgedHeadersAreDroppedOnPublicPathsToo() throws Exception {
        respondOk();

        gateway().post().uri("/api/auth/login").header("X-User-Id", "admin")
                .exchange().expectStatus().isOk();

        RecordedRequest request = forwarded();
        assertThat(request.getHeader("X-User-Id")).isNull();
    }

    @Test
    void tokenFromCookieIsAccepted() throws Exception {
        respondOk();

        gateway().get().uri("/api/payments/pay-1")
                .cookie("token", TestTokens.valid("u-cookie", "Cookie C."))
                .exchange().expectStatus().isOk();

        RecordedRequest request = forwarded();
        assertThat(request.getPath()).isEqualTo("/api/payments/pay-1");
        assertThat(request.getHeader("X-User-Id")).isEqualTo("u-cookie");
    }

    @Test
    void missingNameClaim_stillAuthenticatesWithoutNameHeader() throws Exception {
        respondOk();

        gateway().get().uri("/api/deals/d1")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestTokens.valid("u-noname", null))
                .exchange().expectStatus().isOk();

        RecordedRequest request = forwarded();
        assertThat(request.getHeader("X-User-Id")).isEqualTo("u-noname");
        assertThat(request.getHeader("X-User-Name")).isNull();
    }

    @Test
    void everyPhase1DealEndpointIsRouted() throws Exception {
        String bearer = "Bearer " + TestTokens.valid("u1", "A B.");
        String[][] calls = {
                { "POST", "/api/deals" }, { "GET", "/api/deals/nearby?lat=1&lng=2" }, { "GET", "/api/deals/mine?tab=created" },
                { "GET", "/api/deals/d1?lat=1&lng=2" }, { "POST", "/api/deals/d1/join" },
                { "POST", "/api/deals/d1/leave" }, { "DELETE", "/api/deals/d1" } };
        for (String[] call : calls) {
            respondOk();
            gateway().method(org.springframework.http.HttpMethod.valueOf(call[0])).uri(call[1])
                    .header(HttpHeaders.AUTHORIZATION, bearer).exchange().expectStatus().isOk();
            RecordedRequest request = forwarded();
            assertThat(request.getMethod()).isEqualTo(call[0]);
            assertThat(request.getPath()).isEqualTo(call[1]);
        }
    }

    @Test
    void dealEndpointsNotInThePlanAreNotRouted() {
        String bearer = "Bearer " + TestTokens.valid("u1", "A B.");

        // wrong method on a known path, and a phase 2 path that has no route yet
        gateway().put().uri("/api/deals/d1").header(HttpHeaders.AUTHORIZATION, bearer).exchange().expectStatus().isNotFound();
        gateway().delete().uri("/api/deals").header(HttpHeaders.AUTHORIZATION, bearer).exchange().expectStatus().isNotFound();
        gateway().post().uri("/api/deals/d1/mark-purchased").header(HttpHeaders.AUTHORIZATION, bearer)
                .exchange().expectStatus().isNotFound();
    }

    @Test
    void authRoutesArePublicAndRewrittenToApiV1() throws Exception {
        respondOk();
        respondOk();

        gateway().post().uri("/api/auth/login").bodyValue("{\"phoneNumber\":\"+66812345678\"}")
                .header(HttpHeaders.CONTENT_TYPE, "application/json").exchange().expectStatus().isOk();
        gateway().post().uri("/api/auth/register").header(HttpHeaders.CONTENT_TYPE, "application/json")
                .bodyValue("{}").exchange().expectStatus().isOk();

        assertThat(forwarded().getPath()).isEqualTo("/api/v1/auth/login");
        assertThat(forwarded().getPath()).isEqualTo("/api/v1/auth/register");
    }

    @Test
    void usersRouteIsRewrittenAndNeedsToken() throws Exception {
        respondOk();

        gateway().get().uri("/api/users/me").exchange().expectStatus().isUnauthorized();
        gateway().get().uri("/api/users/me")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestTokens.valid("u1", "A B."))
                .exchange().expectStatus().isOk();

        assertThat(forwarded().getPath()).isEqualTo("/api/v1/users/me");
    }

    @Test
    void notificationsAndWebhookRoutes() throws Exception {
        respondOk();
        respondOk();

        gateway().get().uri("/api/notifications")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestTokens.valid("u1", "A B."))
                .exchange().expectStatus().isOk();
        gateway().post().uri("/webhooks/stripe").header("Stripe-Signature", "t=1,v1=abc")
                .header(HttpHeaders.CONTENT_TYPE, "application/json").bodyValue("{\"raw\":true}")
                .exchange().expectStatus().isOk(); // public: no JWT

        assertThat(forwarded().getPath()).isEqualTo("/api/notifications");
        RecordedRequest webhook = forwarded();
        assertThat(webhook.getPath()).isEqualTo("/webhooks/stripe");
        assertThat(webhook.getHeader("Stripe-Signature")).isEqualTo("t=1,v1=abc");
        assertThat(webhook.getBody().readUtf8()).isEqualTo("{\"raw\":true}");
    }

    @Test
    void protectedRoutes_rejectMissingBadAndExpiredTokens() {
        String expired = TestTokens.token(TestTokens.SECRET, "u1", "A B.", new Date(System.currentTimeMillis() - 1000));
        String wrongKey = TestTokens.token("another-secret-another-secret-0123456789", "u1", "A B.",
                new Date(System.currentTimeMillis() + 60_000));
        String noSub = TestTokens.token(TestTokens.SECRET, null, "A B.", new Date(System.currentTimeMillis() + 60_000));

        gateway().get().uri("/api/deals/d1").exchange().expectStatus().isUnauthorized()
                .expectBody().jsonPath("$.code").isEqualTo("UNAUTHORIZED").jsonPath("$.timestamp").exists();
        for (String bad : new String[] { expired, wrongKey, noSub, "not-a-jwt" }) {
            gateway().get().uri("/api/deals/d1").header(HttpHeaders.AUTHORIZATION, "Bearer " + bad)
                    .exchange().expectStatus().isUnauthorized();
        }
    }

    @Test
    void internalPathsAreNeverRouted_evenWithAValidToken() {
        gateway().post().uri("/internal/dev/payments/pay-1/simulate-success")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + TestTokens.valid("u1", "A B."))
                .exchange().expectStatus().isNotFound()
                .expectBody().jsonPath("$.code").isEqualTo("NOT_FOUND");
    }

    @Test
    void healthIsPublic() {
        gateway().get().uri("/actuator/health").exchange().expectStatus().isOk();
    }
}
