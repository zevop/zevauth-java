package com.zevauth.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zevauth.Auth;
import com.zevauth.HttpTransport;
import com.zevauth.ZevAuthClient;
import com.zevauth.ZevAuthVerifier;
import jakarta.servlet.http.Cookie;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;

/**
 * The starter in a real application context, against the shared fixtures
 * (vendored in the core module) with the clock fixed to their "now".
 */
@SpringBootTest(
    classes = ZevAuthStarterTest.App.class,
    properties = {
      "zevauth.secret-key=sk_test_fixture",
      "zevauth.publishable-key=pk_test_fixture",
      "zevauth.webhook-secret=whsec_fixture_secret_not_for_production_use",
      "zevauth.bridge.enabled=true",
    })
class ZevAuthStarterTest {
  static final Path FIXTURES = Path.of("../core/src/test/resources/fixtures");
  static final ObjectMapper JSON = new ObjectMapper();

  @SpringBootApplication
  static class App {
    /** Your own verifier replaces the auto-configured one; here, one with a fixed clock. */
    @Bean
    ZevAuthVerifier verifier() throws IOException {
      JsonNode tokens = JSON.readTree(FIXTURES.resolve("tokens.json").toFile());
      byte[] discovery = Files.readAllBytes(FIXTURES.resolve("discovery.json"));
      byte[] jwks = Files.readAllBytes(FIXTURES.resolve("jwks.json"));
      HttpTransport transport = request -> new HttpTransport.Response(200, new TreeMap<>(),
          request.uri().getPath().endsWith("/openid-configuration") ? discovery : jwks);
      return ZevAuthVerifier.builder(tokens.get("environmentId").asText())
          .apiUrl("https://api.zevauth.test")
          .transport(transport)
          .clock(Clock.fixed(Instant.ofEpochSecond(tokens.get("now").asLong()), ZoneOffset.UTC))
          .build();
    }

    @RestController
    static class Controller {
      @GetMapping("/api/open")
      Map<String, Object> open(Auth auth) {
        return Map.of("signedIn", auth.isSignedIn());
      }

      @RequireAuth
      @GetMapping("/api/me")
      Map<String, Object> me(Auth auth) {
        Object principal = SecurityContextHolder.getContext().getAuthentication() == null
            ? "" : SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return Map.of("userId", auth.getUserId(), "principal", String.valueOf(principal));
      }

      @RequireAuth(requireMfa = true)
      @GetMapping("/api/payouts")
      Map<String, Object> payouts() {
        return Map.of("ok", true);
      }

      @GetMapping("/dashboard")
      String dashboard(Auth auth) {
        return auth.isSignedIn() ? "hello " + auth.getUserId() : "signed out";
      }
    }
  }

  @Autowired WebApplicationContext context;
  @Autowired ZevAuthRequestFilter filter;
  @Autowired ZevAuthClient client;
  @Autowired ZevAuthWebhooks webhooks;

  MockMvc mvc;
  JsonNode tokens;

  @BeforeEach
  void setUp() throws IOException {
    mvc = MockMvcBuilders.webAppContextSetup(context).addFilters(filter).build();
    tokens = JSON.readTree(FIXTURES.resolve("tokens.json").toFile());
    SecurityContextHolder.clearContext();
  }

  String token(String name) {
    for (JsonNode tc : tokens.get("cases")) if (tc.get("name").asText().equals(name)) return tc.get("token").asText();
    throw new IllegalArgumentException(name);
  }

  @Test
  void autoConfiguresTheClientAndWebhooks() {
    assertThat(client).isNotNull();
    assertThat(webhooks).isNotNull();
  }

  @Test
  void signedInRequestReachesTheController() throws Exception {
    mvc.perform(get("/api/me").header("Authorization", "Bearer " + token("valid")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.userId").value("user_fixture_1"))
        .andExpect(jsonPath("$.principal").value("user_fixture_1"));
  }

  @Test
  void requireAuthRefusesWithTheSharedEnvelope() throws Exception {
    mvc.perform(get("/api/me"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error.code").value("unauthorized"));
    mvc.perform(get("/api/me").header("Authorization", "Bearer " + token("valid_pending_task")))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.error.code").value("session_task_pending"))
        .andExpect(jsonPath("$.error.pendingTasks[0]").value("setup_mfa"));
  }

  @Test
  void requireMfa() throws Exception {
    mvc.perform(get("/api/payouts").header("Authorization", "Bearer " + token("valid")))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.error.code").value("mfa_required"));
    mvc.perform(get("/api/payouts").header("Authorization", "Bearer " + token("valid_mfa")))
        .andExpect(status().isOk());
  }

  @Test
  void unannotatedRoutesStayOpen() throws Exception {
    mvc.perform(get("/api/open")).andExpect(status().isOk()).andExpect(jsonPath("$.signedIn").value(false));
  }

  @Test
  void bridgeSetsTheSessionCookie() throws Exception {
    String set = mvc.perform(post("/zevauth/bridge")
            .header("x-zevauth-bridge", "1")
            .header("Origin", "http://localhost")
            .contentType("application/json")
            .content("{\"token\":\"" + token("valid") + "\"}"))
        .andExpect(status().isNoContent())
        .andReturn().getResponse().getHeader("Set-Cookie");
    assertThat(set).startsWith("__Host-zevauth_session=").contains("HttpOnly").contains("Secure").contains("Max-Age=840");
  }

  @Test
  void bridgeRefusesAForeignOrigin() throws Exception {
    mvc.perform(post("/zevauth/bridge")
            .header("x-zevauth-bridge", "1")
            .header("Origin", "https://evil.example")
            .contentType("application/json")
            .content("{\"token\":\"" + token("valid") + "\"}"))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.error.code").value("bridge_origin_not_allowed"));
  }

  @Test
  void pagesReadTheCookie() throws Exception {
    mvc.perform(get("/dashboard").accept("text/html")
            .cookie(new Cookie("__Host-zevauth_session", token("valid")), new Cookie("__Host-zevauth_client", "1")))
        .andExpect(status().isOk())
        .andExpect(content().string("hello user_fixture_1"));
  }

  @Test
  void expiredCookieGoesThroughTheHandshake() throws Exception {
    mvc.perform(get("/dashboard").accept("text/html")
            .cookie(new Cookie("__Host-zevauth_session", token("expired")), new Cookie("__Host-zevauth_client", "1")))
        .andExpect(status().isFound())
        .andExpect(header().string("Location", "/zevauth/handshake?redirect_url=%2Fdashboard"));
    mvc.perform(get("/zevauth/handshake").param("redirect_url", "/dashboard"))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith("text/html"))
        .andExpect(content().string(org.hamcrest.Matchers.containsString("syncSessionBridge")));
  }
}
