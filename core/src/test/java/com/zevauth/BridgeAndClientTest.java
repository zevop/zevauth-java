package com.zevauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class BridgeAndClientTest {
  private JsonNode tokens;
  private SessionBridge bridge;

  @BeforeEach
  void setUp() throws IOException {
    tokens = ConformanceTest.fixture("tokens.json");
    bridge = SessionBridge.builder(ConformanceTest.verifier(tokens, "jwks.json", null, null)).build();
  }

  private String token(String name) {
    for (JsonNode tc : ConformanceTest.cases(tokens)) {
      if (tc.get("name").asText().equals(name)) return tc.get("token").asText();
    }
    throw new IllegalArgumentException(name);
  }

  private SessionBridge.Outcome page(String path, Map<String, String> cookies) {
    return bridge.authenticate("GET", "text/html,application/xhtml+xml", path, null, cookies);
  }

  @Test
  void readsTheSessionCookie() {
    SessionBridge.Outcome o = page("/dashboard", Map.of("__Host-zevauth_session", token("valid"), "__Host-zevauth_client", "1"));
    assertNull(o.handshake());
    assertEquals("user_fixture_1", o.auth().getUserId());
  }

  @Test
  void expiredCookieRedirectsToTheHandshake() {
    SessionBridge.Outcome o = page("/dashboard?tab=2", Map.of("__Host-zevauth_session", token("expired"), "__Host-zevauth_client", "1"));
    assertNotNull(o.handshake());
    assertEquals(302, o.handshake().status());
    assertEquals("/zevauth/handshake?redirect_url=%2Fdashboard%3Ftab%3D2", o.handshake().headers().get("Location"));
    assertEquals("no-store", o.handshake().headers().get("Cache-Control"));
  }

  @Test
  void clientCookieAloneMeansTheSessionLapsed() {
    assertEquals(302, page("/", Map.of("__Host-zevauth_client", "1")).handshake().status());
  }

  @Test
  void someoneWhoNeverSignedInIsNotSentToTheHandshake() {
    SessionBridge.Outcome o = page("/", Map.of());
    assertNull(o.handshake());
    assertFalse(o.auth().isSignedIn());
  }

  @Test
  void loopGuard() {
    assertNull(page("/?" + SessionBridge.HANDSHAKE_MARKER + "=1", Map.of("__Host-zevauth_client", "1")).handshake());
  }

  @Test
  void nonNavigationGets401() {
    SessionBridge.Outcome o = bridge.authenticate("POST", "application/json", "/api/things", null, Map.of("__Host-zevauth_client", "1"));
    assertEquals(401, o.handshake().status());
    assertTrue(o.handshake().body().contains("session_refresh_required"));
  }

  @Test
  void aRequestWithItsOwnTokenNeverHandshakes() {
    SessionBridge.Outcome o = bridge.authenticate("GET", "text/html", "/", "Bearer " + token("expired"), Map.of("__Host-zevauth_client", "1"));
    assertNull(o.handshake());
  }

  @Test
  void cookieNames() {
    ZevAuthVerifier v = ZevAuthVerifier.builder("env_test_x").build();
    assertEquals("__Host-zevauth_session", SessionBridge.builder(v).build().sessionCookieName());
    assertEquals("__Secure-zevauth_session", SessionBridge.builder(v).cookieDomain("example.com").build().sessionCookieName());
    assertEquals("zevauth_client", SessionBridge.builder(v).secure(false).build().clientCookieName());
  }

  @Test
  void handshakePageGuards() {
    SessionBridge.HandshakeOptions options = new SessionBridge.HandshakeOptions("pk_test_x", "/zevauth/bridge");
    assertTrue(SessionBridge.handshakePage("/dashboard?a=1", options).body().contains("\"back\":\"/dashboard?a=1\\u0026__zevauth_handshake=1\""));
    for (String evil : List.of("//evil.example/x", "/\\evil.example", "https://evil.example")) {
      assertTrue(SessionBridge.handshakePage(evil, options).body().contains("\"back\":\"/?__zevauth_handshake=1\""), evil);
    }
    String body = SessionBridge.handshakePage("/</script><script>alert(1)</script>", options).body();
    assertEquals(2, body.split("</script>", -1).length - 1, "redirect_url escaped the script element");
  }

  @Test
  void clientKeyChecks() {
    assertEquals(ApiException.MISSING_SECRET_KEY, assertThrows(ApiException.class, () -> ZevAuthClient.builder("")).getCode());
    assertEquals(ApiException.WRONG_KEY_TYPE, assertThrows(ApiException.class, () -> ZevAuthClient.builder("pk_test_x")).getCode());
  }

  @Test
  void iterateFollowsCursors() {
    AtomicInteger calls = new AtomicInteger();
    ZevAuthClient client = ZevAuthClient.builder("sk_test_x")
        .transport(request -> {
          int n = calls.incrementAndGet();
          String query = request.uri().getRawQuery();
          assertTrue(query.contains("metadata%5Bplan%5D=pro"), query);
          boolean first = !query.contains("after=");
          String body = "{\"data\":[{\"id\":\"user_" + n + "\"}],\"hasMore\":" + first + ",\"next\":\"cur_" + n + "\",\"totalCount\":2}";
          return new HttpTransport.Response(200, new TreeMap<>(), body.getBytes(StandardCharsets.UTF_8));
        })
        .build();
    List<String> ids = new ArrayList<>();
    for (Models.User u : client.users().iterate(Map.of("metadata.plan", "pro"))) ids.add(u.id());
    assertEquals(List.of("user_1", "user_2"), ids);
  }

  @Test
  void networkErrorsRetryThenReportStatusZero() {
    AtomicInteger calls = new AtomicInteger();
    ZevAuthClient client = ZevAuthClient.builder("sk_test_x")
        .transport(request -> { calls.incrementAndGet(); throw new IOException("connection refused"); })
        .sleeper(d -> {})
        .build();
    ApiException e = assertThrows(ApiException.class, () -> client.organizations().delete("org_1"));
    assertEquals(ApiException.NETWORK_ERROR, e.getCode());
    assertEquals(0, e.getStatus());
    assertEquals(3, calls.get());
  }

  @Test
  void backoff() {
    assertEquals(Duration.ofMillis(200), ZevAuthClient.backoff(0));
    assertEquals(Duration.ofMillis(800), ZevAuthClient.backoff(2));
    assertEquals(Duration.ofSeconds(4), ZevAuthClient.backoff(6));
  }

  @Test
  void pendingTaskRefusalListsTheTasks() throws IOException {
    Auth auth = ConformanceTest.verifier(tokens, "jwks.json", null, null).getAuth("Bearer " + token("valid_pending_task"));
    AuthRefusal refusal = assertThrows(AuthRefusal.class, () -> auth.require(RequireOptions.DEFAULT));
    assertEquals("setup_mfa", Json.MAPPER.readTree(refusal.toJson()).path("error").path("pendingTasks").get(0).asText());
  }
}
