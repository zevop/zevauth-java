package com.zevauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * The shared conformance fixtures (src/test/resources/fixtures, synced from
 * https://github.com/zevop/zevauth-sdk/tree/main/spec), run with the clock
 * fixed to the fixtures' "now".
 */
class ConformanceTest {

  static JsonNode fixture(String name) throws IOException {
    try (InputStream in = ConformanceTest.class.getResourceAsStream("/fixtures/" + name)) {
      assertNotNull(in, "missing fixture " + name);
      return Json.MAPPER.readTree(in);
    }
  }

  static byte[] fixtureBytes(String name) throws IOException {
    try (InputStream in = ConformanceTest.class.getResourceAsStream("/fixtures/" + name)) {
      return in.readAllBytes();
    }
  }

  static HttpTransport.Response ok(byte[] body) {
    return new HttpTransport.Response(200, new TreeMap<>(), body);
  }

  /** Serves discovery and a key set over a fake transport, so the real fetch, cache and rotation paths run. */
  static ZevAuthVerifier verifier(JsonNode tokens, String jwks, String afterRefetch, AtomicInteger fetches) throws IOException {
    byte[] discovery = fixtureBytes("discovery.json");
    byte[] first = fixtureBytes(jwks);
    byte[] later = afterRefetch == null ? first : fixtureBytes(afterRefetch);
    AtomicInteger jwksCalls = new AtomicInteger();
    HttpTransport transport = request -> {
      String path = request.uri().getPath();
      if (path.endsWith("/openid-configuration")) return ok(discovery);
      if (path.endsWith("/jwks.json")) {
        if (fetches != null) fetches.incrementAndGet();
        return ok(jwksCalls.incrementAndGet() == 1 ? first : later);
      }
      return new HttpTransport.Response(404, new TreeMap<>(), new byte[0]);
    };
    return ZevAuthVerifier.builder(tokens.get("environmentId").asText())
        .apiUrl("https://api.zevauth.test")
        .transport(transport)
        .clock(Clock.fixed(Instant.ofEpochSecond(tokens.get("now").asLong()), ZoneOffset.UTC))
        .clockSkew(Duration.ofSeconds(tokens.get("clockSkewSeconds").asInt()))
        .build();
  }

  static String text(JsonNode node) {
    return node == null || node.isNull() ? null : node.asText();
  }

  static List<JsonNode> cases(JsonNode fixture) {
    return StreamSupport.stream(fixture.get("cases").spliterator(), false).toList();
  }

  @TestFactory
  Stream<DynamicTest> tokens() throws IOException {
    JsonNode fx = fixture("tokens.json");
    List<JsonNode> cases = cases(fx);
    assertEquals(17, cases.size());
    return cases.stream().map(tc -> DynamicTest.dynamicTest(tc.get("name").asText(), () -> {
      ZevAuthVerifier v = verifier(fx, tc.get("jwks").asText(), text(tc.get("jwksAfterRefetch")), null);
      String token = tc.get("token").asText();
      JsonNode expect = tc.get("expect");
      if (expect.get("ok").asBoolean()) {
        assertNotNull(v.verify(token));
      } else {
        VerifyException e = assertThrows(VerifyException.class, () -> v.verify(token));
        assertEquals(expect.get("error").asText(), e.getCode());
      }

      Auth auth = v.getAuth("Bearer " + token);
      JsonNode want = tc.get("auth");
      if (want != null) {
        assertEquals(want.get("isSignedIn").asBoolean(), auth.isSignedIn());
        if (auth.isSignedIn()) {
          assertEquals(text(want.get("userId")), auth.getUserId());
          assertEquals(text(want.get("sessionId")), auth.getSessionId());
          assertEquals(text(want.get("organizationId")), auth.getOrganizationId());
          assertEquals(text(want.get("organizationRole")), auth.getOrganizationRole());
          List<String> tasks = new ArrayList<>();
          want.get("pendingTasks").forEach(t -> tasks.add(t.asText()));
          assertEquals(tasks, auth.getPendingTasks());
          assertEquals(want.get("isMfaVerified").asBoolean(), auth.isMfaVerified());
        }
      }
      if (tc.has("has")) {
        for (JsonNode h : tc.get("has")) {
          JsonNode check = h.get("check");
          assertEquals(h.get("result").asBoolean(), auth.has(text(check.get("role")), text(check.get("permission"))), h.toString());
        }
      }
      if (tc.has("requireAuth")) {
        for (JsonNode rc : tc.get("requireAuth")) {
          JsonNode o = rc.get("options");
          RequireOptions options = new RequireOptions(o.path("allowPendingTasks").asBoolean(), o.path("requireMfa").asBoolean());
          JsonNode result = rc.get("result");
          if (result.get("ok").asBoolean()) {
            auth.require(options);
          } else {
            AuthRefusal refusal = assertThrows(AuthRefusal.class, () -> auth.require(options));
            assertEquals(result.get("status").asInt(), refusal.getStatus());
            assertEquals(result.get("code").asText(), refusal.getCode());
            JsonNode body = Json.MAPPER.readTree(refusal.toJson());
            assertEquals(result.get("code").asText(), body.path("error").path("code").asText());
          }
        }
      }
    }));
  }

  @Test
  void unknownKidRefetchesOncePerCooldown() throws Exception {
    JsonNode fx = fixture("tokens.json");
    String valid = null;
    String unknown = null;
    for (JsonNode tc : cases(fx)) {
      if (tc.get("name").asText().equals("valid")) valid = tc.get("token").asText();
      if (tc.get("name").asText().equals("unknown_kid")) unknown = tc.get("token").asText();
    }
    AtomicInteger fetches = new AtomicInteger();
    ZevAuthVerifier v = verifier(fx, "jwks.json", null, fetches);
    v.verify(valid);
    for (int i = 0; i < 5; i++) {
      String t = unknown;
      assertThrows(VerifyException.class, () -> v.verify(t));
    }
    assertEquals(2, fetches.get(), "one initial fetch, one refetch; the rest inside the cooldown");
  }

  @Test
  void localKeySetNeverFetches() throws Exception {
    JsonNode fx = fixture("tokens.json");
    ZevAuthVerifier v = ZevAuthVerifier.builder(fx.get("environmentId").asText())
        .localKeys(fx.get("issuer").asText(), new String(fixtureBytes("jwks.json"), StandardCharsets.UTF_8))
        .transport(request -> fail("fetched with a local key set"))
        .clock(Clock.fixed(Instant.ofEpochSecond(fx.get("now").asLong()), ZoneOffset.UTC))
        .build();
    assertEquals("user_fixture_1", v.verify(cases(fx).get(0).get("token").asText()).getSubject());
  }

  @Test
  void unreachableKeysAreJwksUnavailable() throws Exception {
    JsonNode fx = fixture("tokens.json");
    ZevAuthVerifier v = ZevAuthVerifier.builder(fx.get("environmentId").asText())
        .transport(request -> { throw new IOException("connection refused"); })
        .clock(Clock.fixed(Instant.ofEpochSecond(fx.get("now").asLong()), ZoneOffset.UTC))
        .build();
    VerifyException e = assertThrows(VerifyException.class, () -> v.verify(cases(fx).get(0).get("token").asText()));
    assertEquals(VerifyException.JWKS_UNAVAILABLE, e.getCode());
    assertFalse(v.getAuth("Bearer " + cases(fx).get(0).get("token").asText()).isSignedIn(), "getAuth never throws");
  }

  @Test
  void bearer() throws IOException {
    for (JsonNode tc : cases(fixture("bearer.json"))) {
      assertEquals(text(tc.get("token")), Bearer.from(text(tc.get("header"))), tc.toString());
    }
  }

  @TestFactory
  Stream<DynamicTest> webhooks() throws IOException {
    JsonNode fx = fixture("webhooks.json");
    Clock clock = Clock.fixed(Instant.ofEpochSecond(fx.get("now").asLong()), ZoneOffset.UTC);
    Duration tolerance = Duration.ofSeconds(fx.get("toleranceSeconds").asInt());
    String secret = fx.get("secret").asText();
    return cases(fx).stream().map(tc -> DynamicTest.dynamicTest(tc.get("name").asText(), () -> {
      byte[] payload = tc.get("payload").asText().getBytes(StandardCharsets.UTF_8);
      String signature = tc.get("signature").asText();
      if (tc.get("valid").asBoolean()) {
        WebhookEvent event = Webhooks.constructEvent(payload, signature, secret, tolerance, clock);
        assertNotNull(event.id());
        assertNotNull(event.type());
      } else {
        WebhookException e = assertThrows(WebhookException.class, () -> Webhooks.verify(payload, signature, secret, tolerance, clock));
        assertEquals(tc.get("error").asText(), e.getCode());
      }
    }));
  }

  @TestFactory
  Stream<DynamicTest> apiErrors() throws IOException {
    return cases(fixture("api-errors.json")).stream().map(tc -> DynamicTest.dynamicTest(tc.get("name").asText(), () -> {
      byte[] body = tc.has("bodyText")
          ? tc.get("bodyText").asText().getBytes(StandardCharsets.UTF_8)
          : Json.MAPPER.writeValueAsBytes(tc.get("body"));
      Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
      tc.get("headers").fields().forEachRemaining(e -> headers.put(e.getKey(), List.of(e.getValue().asText())));
      AtomicInteger calls = new AtomicInteger();
      List<Duration> waits = new ArrayList<>();
      ZevAuthClient client = ZevAuthClient.builder("sk_test_fixture")
          .apiUrl("https://api.zevauth.test")
          .transport(request -> {
            calls.incrementAndGet();
            assertEquals("zevauth-java/" + Version.VERSION, request.headers().get("User-Agent"));
            assertNull(request.headers().get("Idempotency-Key"));
            return new HttpTransport.Response(tc.get("status").asInt(), headers, body);
          })
          .sleeper(waits::add)
          .build();
      JsonNode expect = tc.get("expect");
      ApiException e = assertThrows(ApiException.class, () -> client.users().get("user_1"));
      assertEquals(expect.get("code").asText(), e.getCode());
      assertEquals(expect.get("status").asInt(), e.getStatus());
      assertEquals(text(expect.get("requestId")), e.getRequestId());
      assertEquals(expect.get("retry").asBoolean() ? 3 : 1, calls.get());
      if (expect.has("retryAfterSeconds")) {
        assertEquals(Duration.ofSeconds(expect.get("retryAfterSeconds").asInt()), waits.get(0));
      }
    }));
  }

  @TestFactory
  Stream<DynamicTest> bridge() throws IOException {
    JsonNode fx = fixture("bridge.json");
    JsonNode tokens = fixture("tokens.json");
    String appOrigin = fx.get("appOrigin").asText();
    return cases(fx).stream().map(tc -> DynamicTest.dynamicTest(tc.get("name").asText(), () -> {
      SessionBridge bridge = SessionBridge.builder(verifier(tokens, "jwks.json", null, null)).build();
      JsonNode request = tc.get("request");
      byte[] body = request.has("body") ? Json.MAPPER.writeValueAsBytes(request.get("body")) : new byte[0];
      SessionBridge.Response r = bridge.handle(request.get("method").asText(),
          request.get("bridgeHeader").asBoolean() ? "1" : null, text(request.get("origin")), appOrigin, body);

      JsonNode expect = tc.get("expect");
      assertEquals(expect.get("status").asInt(), r.status(), String.valueOf(r.body()));
      if (expect.has("code")) {
        assertEquals(expect.get("code").asText(), Json.MAPPER.readTree(r.body()).path("error").path("code").asText());
      }
      switch (expect.get("cookie").asText()) {
        case "unchanged" -> assertTrue(r.setCookies().isEmpty(), r.setCookies().toString());
        case "cleared" -> {
          assertEquals(2, r.setCookies().size());
          r.setCookies().forEach(c -> assertTrue(c.contains("Max-Age=0"), c));
        }
        case "set" -> {
          String session = r.setCookies().get(0);
          assertTrue(session.startsWith("__Host-zevauth_session="), session);
          assertTrue(session.contains("Max-Age=" + expect.get("maxAgeSeconds").asInt()), session);
          assertTrue(session.contains("HttpOnly") && session.contains("Secure") && session.contains("SameSite=Lax"), session);
          assertTrue(r.setCookies().get(1).startsWith("__Host-zevauth_client=1;"), r.setCookies().get(1));
        }
        default -> fail("unknown cookie expectation");
      }
    }));
  }
}
