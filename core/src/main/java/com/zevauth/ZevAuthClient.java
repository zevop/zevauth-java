package com.zevauth;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonNode;
import com.zevauth.Models.Membership;
import com.zevauth.Models.Organization;
import com.zevauth.Models.OrganizationWithMembers;
import com.zevauth.Models.Page;
import com.zevauth.Models.SetBlockedResult;
import com.zevauth.Models.User;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.StringJoiner;

/**
 * Calls the ZevAuth backend API with a secret key. Thread-safe.
 *
 * <pre>{@code
 * ZevAuthClient zevauth = ZevAuthClient.builder(System.getenv("ZEVAUTH_SECRET_KEY")).build();
 * Models.User user = zevauth.users().get("user_…");
 * for (Models.User u : zevauth.users().iterate(Map.of())) { … }
 * }</pre>
 */
public final class ZevAuthClient {
  private static final Duration MAX_RETRY_AFTER = Duration.ofSeconds(10);
  private static final Duration MAX_BACKOFF = Duration.ofSeconds(4);

  /** Waits between retries. Replace it in tests. */
  @FunctionalInterface
  public interface Sleeper {
    void sleep(Duration duration) throws InterruptedException;
  }

  private final String secretKey;
  private final String apiUrl;
  private final Duration timeout;
  private final int maxRetries;
  private final HttpTransport transport;
  private final Sleeper sleeper;
  private final Users users = new Users();
  private final Organizations organizations = new Organizations();

  private ZevAuthClient(Builder b) {
    this.secretKey = b.secretKey;
    this.apiUrl = b.apiUrl.replaceAll("/+$", "");
    this.timeout = b.timeout;
    this.maxRetries = b.maxRetries;
    this.transport = b.transport == null ? HttpTransport.jdk() : b.transport;
    this.sleeper = b.sleeper;
  }

  /**
   * A secret key is required (sk_test_… / sk_live_…). A publishable key is
   * refused: it cannot call the backend API, and a server holding one
   * usually means the keys were swapped.
   */
  public static Builder builder(String secretKey) {
    if (secretKey == null || secretKey.isEmpty()) {
      throw new ApiException(ApiException.MISSING_SECRET_KEY, 0, "a secret key (sk_…) is required", null, null);
    }
    if (secretKey.startsWith("pk_")) {
      throw new ApiException(ApiException.WRONG_KEY_TYPE, 0,
          "that is a publishable key; the backend API needs your secret key (sk_…)", null, null);
    }
    return new Builder(secretKey);
  }

  public Users users() { return users; }
  public Organizations organizations() { return organizations; }

  // ── HTTP ─────────────────────────────────────────────────────────

  JsonNode request(String method, String path, Map<String, String> query, Object body) {
    String target = apiUrl + path + encodeQuery(query);
    byte[] payload = body == null ? null : Json.write(body).getBytes(StandardCharsets.UTF_8);
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("Authorization", "Bearer " + secretKey);
    headers.put("Accept", "application/json");
    headers.put("User-Agent", Version.USER_AGENT);
    if (payload != null) headers.put("Content-Type", "application/json");

    for (int attempt = 0; ; attempt++) {
      HttpTransport.Response response;
      try {
        response = transport.send(new HttpTransport.Request(method, URI.create(target), headers, payload, timeout));
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new ApiException(ApiException.NETWORK_ERROR, 0, "interrupted", null, e);
      } catch (IOException e) {
        ApiException error = new ApiException(ApiException.NETWORK_ERROR, 0, String.valueOf(e.getMessage()), null, e);
        if (attempt >= maxRetries) throw error;
        pause(backoff(attempt), error);
        continue;
      }

      if (response.status() >= 200 && response.status() < 300) {
        try {
          return response.body() == null || response.body().length == 0
              ? null
              : Json.MAPPER.readTree(response.body());
        } catch (IOException e) {
          throw new ApiException(ApiException.REQUEST_FAILED, response.status(), "unreadable response", null, e);
        }
      }

      ApiException error = errorFrom(response);
      // Retry only what certainly did not run: never a 500, never another 4xx.
      if (!retryable(response.status()) || attempt >= maxRetries) throw error;
      Duration wait = retryAfter(response.header("retry-after"));
      pause(wait != null ? min(wait, MAX_RETRY_AFTER) : backoff(attempt), error);
    }
  }

  private void pause(Duration wait, ApiException error) {
    try {
      sleeper.sleep(wait);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw error;
    }
  }

  static ApiException errorFrom(HttpTransport.Response response) {
    String code = ApiException.REQUEST_FAILED;
    String message = "HTTP " + response.status();
    try {
      JsonNode node = response.body() == null ? null : Json.MAPPER.readTree(response.body());
      JsonNode error = node == null ? null : node.path("error");
      if (error != null && error.hasNonNull("code")) {
        code = error.get("code").asText();
        if (error.hasNonNull("message")) message = error.get("message").asText();
      }
    } catch (IOException ignored) {
      // Not JSON: request_failed.
    }
    return new ApiException(code, response.status(), message, response.header("x-request-id"), null);
  }

  static boolean retryable(int status) {
    return status == 429 || status == 502 || status == 503 || status == 504;
  }

  static Duration backoff(int attempt) {
    long millis = 200L << Math.min(attempt, 10);
    Duration d = Duration.ofMillis(millis);
    return d.compareTo(MAX_BACKOFF) > 0 ? MAX_BACKOFF : d;
  }

  private static Duration retryAfter(String header) {
    if (header == null) return null;
    try {
      long seconds = Long.parseLong(header.trim());
      return seconds < 0 ? null : Duration.ofSeconds(seconds);
    } catch (NumberFormatException e) {
      return null;
    }
  }

  private static Duration min(Duration a, Duration b) {
    return a.compareTo(b) <= 0 ? a : b;
  }

  private static String encodeQuery(Map<String, String> query) {
    if (query == null || query.isEmpty()) return "";
    StringJoiner joiner = new StringJoiner("&", "?", "");
    query.forEach((k, v) -> {
      if (v != null) joiner.add(enc(k) + "=" + enc(v));
    });
    return joiner.length() == 1 ? "" : joiner.toString();
  }

  static String enc(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }

  private <T> T as(JsonNode node, Class<T> type) {
    return node == null ? null : Json.MAPPER.convertValue(node, type);
  }

  private <T> T as(JsonNode node, JavaType type) {
    return node == null ? null : Json.MAPPER.convertValue(node, type);
  }

  // ── Resources ────────────────────────────────────────────────────

  /** {@code client.users()}. */
  public final class Users {
    private Users() {}

    /**
     * One page of users. Params: {@code limit}, {@code after}, {@code query},
     * and {@code metadata.<key>} for metadata filters (ANDed).
     */
    public Page<User> list(Map<String, String> params) {
      Map<String, String> query = new LinkedHashMap<>();
      (params == null ? Map.<String, String>of() : params).forEach((k, v) -> {
        // The API reads the bracketed form.
        query.put(k.startsWith("metadata.") ? "metadata[" + k.substring("metadata.".length()) + "]" : k, v);
      });
      JavaType type = Json.MAPPER.getTypeFactory().constructParametricType(Page.class, User.class);
      return as(request("GET", "/v1/users", query, null), type);
    }

    /** Every user matching params, fetching pages as iteration needs them. */
    public Iterable<User> iterate(Map<String, String> params) {
      Map<String, String> base = params == null ? Map.of() : params;
      return () -> new Iterator<>() {
        private final Deque<User> buffer = new ArrayDeque<>();
        private String after;
        private boolean done;

        @Override
        public boolean hasNext() {
          while (buffer.isEmpty() && !done) {
            Map<String, String> query = new LinkedHashMap<>(base);
            if (after != null) query.put("after", after);
            Page<User> page = list(query);
            if (page.data() != null) buffer.addAll(page.data());
            if (page.hasMore() && page.next() != null && !page.next().isEmpty()) after = page.next();
            else done = true;
          }
          return !buffer.isEmpty();
        }

        @Override
        public User next() {
          if (!hasNext()) throw new NoSuchElementException();
          return buffer.removeFirst();
        }
      };
    }

    public User get(String userId) {
      return as(request("GET", "/v1/users/" + enc(userId), null, null), User.class);
    }

    /** Fields as the API names them: email, password, firstName, publicMetadata, … */
    public User create(Map<String, Object> params) {
      return as(request("POST", "/v1/users", null, params), User.class);
    }

    /** Only the fields present change; a null value clears that field. */
    public User update(String userId, Map<String, Object> params) {
      return as(request("PATCH", "/v1/users/" + enc(userId), null, params), User.class);
    }

    /** Blocking also ends the user's sessions. */
    public SetBlockedResult setBlocked(String userId, boolean blocked) {
      return as(request("POST", "/v1/users/" + enc(userId) + "/blocked", null, Map.of("blocked", blocked)),
          SetBlockedResult.class);
    }

    /** Ends every session the user has; returns how many. */
    public int revokeSessions(String userId) {
      JsonNode node = request("POST", "/v1/users/" + enc(userId) + "/sessions/revoke", null, null);
      return node == null ? 0 : node.path("sessionsRevoked").asInt();
    }

    /** Removes the user's second factors, for support. Sessions stay unless asked. */
    public void resetMfa(String userId, boolean revokeSessions) {
      request("DELETE", "/v1/users/" + enc(userId) + "/mfa",
          revokeSessions ? Map.of("revokeSessions", "true") : null, null);
    }

    public void delete(String userId) {
      request("DELETE", "/v1/users/" + enc(userId), null, null);
    }
  }

  /** {@code client.organizations()}. */
  public final class Organizations {
    private Organizations() {}

    public List<Membership> listForUser(String userId) {
      JsonNode node = request("GET", "/v1/organizations", Map.of("userId", Objects.requireNonNull(userId)), null);
      JavaType type = Json.MAPPER.getTypeFactory().constructCollectionType(List.class, Membership.class);
      return node == null ? List.of() : as(node.path("data"), type);
    }

    public OrganizationWithMembers get(String organizationId) {
      return as(request("GET", "/v1/organizations/" + enc(organizationId), null, null), OrganizationWithMembers.class);
    }

    /** Params: name, slug?, createdBy (becomes the first member), maxMembers?. */
    public Organization create(Map<String, Object> params) {
      JsonNode node = request("POST", "/v1/organizations", null, params);
      return node == null ? null : as(node.path("organization"), Organization.class);
    }

    /** Only the fields present change, e.g. name, slug, imageUrl, requireMfa. */
    public Organization update(String organizationId, Map<String, Object> params) {
      JsonNode node = request("PATCH", "/v1/organizations/" + enc(organizationId), null, params);
      return node == null ? null : as(node.path("organization"), Organization.class);
    }

    public void delete(String organizationId) {
      request("DELETE", "/v1/organizations/" + enc(organizationId), null, null);
    }

    /** Returns the member's role. */
    public String addMember(String organizationId, String userId, String role) {
      Map<String, Object> body = new LinkedHashMap<>();
      body.put("userId", userId);
      if (role != null) body.put("role", role);
      JsonNode node = request("POST", "/v1/organizations/" + enc(organizationId) + "/members", null, body);
      return node == null ? null : node.path("role").asText(null);
    }

    public void removeMember(String organizationId, String userId) {
      request("DELETE", "/v1/organizations/" + enc(organizationId) + "/members/" + enc(userId), null, null);
    }
  }

  /** Configures a {@link ZevAuthClient}. */
  public static final class Builder {
    private final String secretKey;
    private String apiUrl = ZevAuthVerifier.DEFAULT_API_URL;
    private Duration timeout = Duration.ofSeconds(15);
    private int maxRetries = 2;
    private HttpTransport transport;
    private Sleeper sleeper = d -> Thread.sleep(d.toMillis());

    private Builder(String secretKey) {
      this.secretKey = secretKey;
    }

    public Builder apiUrl(String apiUrl) { this.apiUrl = Objects.requireNonNull(apiUrl); return this; }
    /** Per attempt. Defaults to 15 seconds. */
    public Builder timeout(Duration timeout) { this.timeout = Objects.requireNonNull(timeout); return this; }
    /** Retries for 429, 502, 503, 504 and network failures. Defaults to 2. */
    public Builder maxRetries(int maxRetries) { this.maxRetries = Math.max(0, maxRetries); return this; }
    public Builder transport(HttpTransport transport) { this.transport = transport; return this; }
    public Builder sleeper(Sleeper sleeper) { this.sleeper = Objects.requireNonNull(sleeper); return this; }

    public ZevAuthClient build() {
      return new ZevAuthClient(this);
    }
  }
}
