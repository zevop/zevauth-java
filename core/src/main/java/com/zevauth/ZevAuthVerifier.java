package com.zevauth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Checks ZevAuth session tokens. Thread-safe: create one per environment
 * and share it.
 *
 * <pre>{@code
 * ZevAuthVerifier verifier = ZevAuthVerifier.builder("env_live_…").build();
 * Auth auth = verifier.getAuth(request.getHeader("Authorization"));
 * }</pre>
 */
public final class ZevAuthVerifier {
  public static final String DEFAULT_API_URL = "https://api.zevauth.net";

  private static final ObjectMapper JSON = new ObjectMapper();
  private static final Duration MAX_KEY_CACHE = Duration.ofMinutes(10);

  private final String environmentId;
  private final String apiUrl;
  private final boolean local;
  private final HttpTransport transport;
  private final Clock clock;
  private final Duration clockSkew;
  private final Duration keyCacheTtl;
  private final Duration refetchCooldown;

  // Guarded by `this`. Holding the lock while fetching is what makes
  // concurrent first requests share one fetch.
  private String issuer;
  private String jwksUri;
  private Map<String, RSAPublicKey> keys;
  private Instant fetchedAt = Instant.EPOCH;
  private Instant lastRefetch = Instant.EPOCH;

  private ZevAuthVerifier(Builder b) {
    this.environmentId = b.environmentId;
    this.apiUrl = b.apiUrl.replaceAll("/+$", "");
    this.local = b.jwks != null;
    this.transport = b.transport;
    this.clock = b.clock;
    this.clockSkew = b.clockSkew;
    this.keyCacheTtl = b.keyCacheTtl.compareTo(MAX_KEY_CACHE) > 0 || b.keyCacheTtl.isNegative() ? MAX_KEY_CACHE : b.keyCacheTtl;
    this.refetchCooldown = b.refetchCooldown;
    if (local) {
      this.issuer = b.issuer;
      try {
        this.keys = parseJwks(b.jwks);
      } catch (Exception e) {
        throw new IllegalArgumentException("zevauth: unreadable local JWKS", e);
      }
    }
  }

  public static Builder builder(String environmentId) {
    return new Builder(environmentId);
  }

  public String getEnvironmentId() {
    return environmentId;
  }

  Clock clock() {
    return clock;
  }

  /**
   * Verifies a token in the contract's order (§1.3) and returns its claims.
   *
   * @throws VerifyException naming why it was refused
   */
  public ZevAuthClaims verify(String token) throws VerifyException {
    if (token == null) throw new VerifyException(VerifyException.MALFORMED_TOKEN, "no token");
    String[] parts = token.split("\\.", -1);
    if (parts.length != 3) throw new VerifyException(VerifyException.MALFORMED_TOKEN, "not a JWT");

    Map<String, Object> header = decodeSegment(parts[0], "header");
    Map<String, Object> payload = decodeSegment(parts[1], "payload");

    // Never let the token choose the algorithm: refuse before any key is
    // looked at, so none and HS256 key confusion never reach a verifier.
    Object alg = header.get("alg");
    if (!"RS256".equals(alg)) {
      throw new VerifyException(VerifyException.UNSUPPORTED_ALGORITHM, "alg " + alg);
    }

    Object kid = header.get("kid");
    KeyAndIssuer key = key(kid instanceof String ? (String) kid : null);

    try {
      SignedJWT jwt = SignedJWT.parse(token);
      if (!jwt.verify(new RSASSAVerifier(key.key))) {
        throw new VerifyException(VerifyException.INVALID_SIGNATURE, null);
      }
    } catch (java.text.ParseException e) {
      throw new VerifyException(VerifyException.MALFORMED_TOKEN, "unparseable", e);
    } catch (JOSEException e) {
      throw new VerifyException(VerifyException.INVALID_SIGNATURE, e.getMessage(), e);
    }

    ZevAuthClaims.checkTypes(payload);
    ZevAuthClaims claims = new ZevAuthClaims(payload);
    if (!Objects.equals(claims.getIssuer(), key.issuer)) {
      throw new VerifyException(VerifyException.INVALID_ISSUER, claims.getIssuer());
    }
    if (!audienceIs(payload.get("aud"))) {
      throw new VerifyException(VerifyException.INVALID_AUDIENCE, null);
    }

    Instant now = clock.instant();
    if (payload.containsKey("exp") && now.isAfter(Instant.ofEpochSecond(claims.getExpiresAt()).plus(clockSkew))) {
      throw new VerifyException(VerifyException.TOKEN_EXPIRED, null);
    }
    if (payload.containsKey("nbf") && now.isBefore(Instant.ofEpochSecond(claims.getNotBefore()).minus(clockSkew))) {
      throw new VerifyException(VerifyException.TOKEN_NOT_YET_VALID, null);
    }
    return claims;
  }

  /**
   * Reads an {@code Authorization} header value and verifies it. Never
   * throws for a missing, expired or forged token: those mean signed out.
   */
  public Auth getAuth(String authorizationHeader) {
    String token = Bearer.from(authorizationHeader);
    if (token == null) return Auth.signedOut();
    try {
      return Auth.from(verify(token));
    } catch (VerifyException e) {
      return Auth.signedOut();
    }
  }

  /** {@link #getAuth} that refuses: throws {@link AuthRefusal} (401 / 403). */
  public Auth requireAuth(String authorizationHeader, RequireOptions options) throws AuthRefusal {
    Auth auth = getAuth(authorizationHeader);
    auth.require(options);
    return auth;
  }

  private boolean audienceIs(Object aud) {
    if (aud instanceof String) return aud.equals(environmentId);
    if (aud instanceof List) return ((List<?>) aud).contains(environmentId);
    return false;
  }

  private record KeyAndIssuer(RSAPublicKey key, String issuer) {}

  /** The key for kid, with one refetch for an unknown kid per cooldown. */
  private synchronized KeyAndIssuer key(String kid) throws VerifyException {
    Instant now = clock.instant();
    if (!local && (keys == null || Duration.between(fetchedAt, now).compareTo(keyCacheTtl) > 0)) {
      fetch();
    }
    RSAPublicKey key = kid == null ? null : keys.get(kid);
    if (key == null && !local && Duration.between(lastRefetch, now).compareTo(refetchCooldown) >= 0) {
      lastRefetch = now;
      fetch();
      key = kid == null ? null : keys.get(kid);
    }
    if (key == null) throw new VerifyException(VerifyException.UNKNOWN_KEY, kid);
    return new KeyAndIssuer(key, issuer);
  }

  private void fetch() throws VerifyException {
    if (jwksUri == null) {
      String url = apiUrl + "/v1/" + URLEncoder.encode(environmentId, StandardCharsets.UTF_8) + "/.well-known/openid-configuration";
      Map<String, Object> doc = getJson(url);
      Object iss = doc.get("issuer");
      Object uri = doc.get("jwks_uri");
      if (!(iss instanceof String) || !(uri instanceof String)) {
        throw new VerifyException(VerifyException.JWKS_UNAVAILABLE, "discovery document is missing issuer or jwks_uri");
      }
      issuer = (String) iss;
      jwksUri = (String) uri;
    }
    byte[] body = getBytes(jwksUri);
    try {
      keys = parseJwks(new String(body, StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new VerifyException(VerifyException.JWKS_UNAVAILABLE, "unreadable key set", e);
    }
    fetchedAt = clock.instant();
  }

  private Map<String, Object> getJson(String url) throws VerifyException {
    try {
      return JSON.readValue(getBytes(url), new TypeReference<Map<String, Object>>() {});
    } catch (VerifyException e) {
      throw e;
    } catch (Exception e) {
      throw new VerifyException(VerifyException.JWKS_UNAVAILABLE, "not JSON: " + url, e);
    }
  }

  private byte[] getBytes(String url) throws VerifyException {
    try {
      HttpTransport.Response response = transport.send(new HttpTransport.Request(
          "GET", URI.create(url), Map.of("Accept", "application/json", "User-Agent", Version.USER_AGENT), null, Duration.ofSeconds(10)));
      if (response.status() != 200) {
        throw new VerifyException(VerifyException.JWKS_UNAVAILABLE, url + " answered " + response.status());
      }
      return response.body();
    } catch (VerifyException e) {
      throw e;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new VerifyException(VerifyException.JWKS_UNAVAILABLE, "interrupted", e);
    } catch (Exception e) {
      throw new VerifyException(VerifyException.JWKS_UNAVAILABLE, e.getMessage(), e);
    }
  }

  private static Map<String, RSAPublicKey> parseJwks(String json) throws Exception {
    Map<String, RSAPublicKey> out = new HashMap<>();
    for (JWK jwk : JWKSet.parse(json).getKeys()) {
      if (!(jwk instanceof RSAKey)) continue;
      if (jwk.getAlgorithm() != null && !"RS256".equals(jwk.getAlgorithm().getName())) continue;
      if (jwk.getKeyUse() != null && !"sig".equals(jwk.getKeyUse().identifier())) continue;
      out.put(jwk.getKeyID(), ((RSAKey) jwk).toRSAPublicKey());
    }
    return out;
  }

  private static Map<String, Object> decodeSegment(String segment, String what) throws VerifyException {
    try {
      return JSON.readValue(Base64.getUrlDecoder().decode(segment), new TypeReference<Map<String, Object>>() {});
    } catch (Exception e) {
      throw new VerifyException(VerifyException.MALFORMED_TOKEN, "unreadable " + what, e);
    }
  }

  /** Configures a {@link ZevAuthVerifier}. */
  public static final class Builder {
    private final String environmentId;
    private String apiUrl = DEFAULT_API_URL;
    private String issuer;
    private String jwks;
    private HttpTransport transport;
    private Clock clock = Clock.systemUTC();
    private Duration clockSkew = Duration.ofSeconds(5);
    private Duration keyCacheTtl = MAX_KEY_CACHE;
    private Duration refetchCooldown = Duration.ofSeconds(30);

    private Builder(String environmentId) {
      if (environmentId == null || environmentId.isEmpty()) {
        throw new IllegalArgumentException("zevauth: an environment id (env_test_… or env_live_…) is required");
      }
      this.environmentId = environmentId;
    }

    /** Defaults to https://api.zevauth.net. The issuer is read from discovery, never built from this. */
    public Builder apiUrl(String apiUrl) { this.apiUrl = Objects.requireNonNull(apiUrl); return this; }

    /** A local key set instead of fetching one, for tests and air-gapped servers. */
    public Builder localKeys(String issuer, String jwksJson) {
      this.issuer = Objects.requireNonNull(issuer);
      this.jwks = Objects.requireNonNull(jwksJson);
      return this;
    }

    public Builder transport(HttpTransport transport) { this.transport = transport; return this; }
    public Builder clock(Clock clock) { this.clock = Objects.requireNonNull(clock); return this; }
    public Builder clockSkew(Duration skew) { this.clockSkew = Objects.requireNonNull(skew); return this; }
    /** Capped at 10 minutes. */
    public Builder keyCacheTtl(Duration ttl) { this.keyCacheTtl = Objects.requireNonNull(ttl); return this; }
    public Builder refetchCooldown(Duration cooldown) { this.refetchCooldown = Objects.requireNonNull(cooldown); return this; }

    public ZevAuthVerifier build() {
      if (transport == null) transport = HttpTransport.jdk();
      return new ZevAuthVerifier(this);
    }
  }
}
