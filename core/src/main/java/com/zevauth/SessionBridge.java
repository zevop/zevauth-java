package com.zevauth;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Lets server-rendered pages know who is signed in (contract §5). The
 * browser SDK posts its access token to the bridge endpoint whenever it
 * changes; the bridge keeps it in your own HttpOnly cookie. The server
 * never refreshes: refresh tokens rotate on every use, so only the browser
 * may.
 *
 * <p>Framework-neutral. Use {@code com.zevauth.servlet} for Jakarta
 * Servlet, or the Spring Boot starter, which wire this up for you.
 */
public final class SessionBridge {
  public static final String BRIDGE_HEADER = "x-zevauth-bridge";
  public static final String HANDSHAKE_MARKER = "__zevauth_handshake";
  public static final String DEFAULT_HANDSHAKE_PATH = "/zevauth/handshake";
  public static final String DEFAULT_UI_SCRIPT_URL =
      "https://cdn.jsdelivr.net/npm/@zevauth/ui@0/dist/zevauth-ui.global.js";
  private static final int CLIENT_COOKIE_MAX_AGE = 30 * 24 * 60 * 60;

  private final ZevAuthVerifier verifier;
  private final List<String> allowedOrigins;
  private final String cookieDomain;
  private final boolean secure;
  private final String handshakePath;

  private SessionBridge(Builder b) {
    this.verifier = Objects.requireNonNull(b.verifier, "verifier");
    this.allowedOrigins = List.copyOf(b.allowedOrigins);
    this.cookieDomain = b.cookieDomain;
    this.secure = b.secure;
    this.handshakePath = b.handshakePath;
  }

  public static Builder builder(ZevAuthVerifier verifier) {
    return new Builder(verifier);
  }

  public String sessionCookieName() { return prefix() + "zevauth_session"; }
  public String clientCookieName() { return prefix() + "zevauth_client"; }
  public String getHandshakePath() { return handshakePath; }

  private String prefix() {
    if (!secure) return "";
    return cookieDomain != null ? "__Secure-" : "__Host-";
  }

  /** A response for the adapter to write. {@code body} is JSON or HTML, or null. */
  public record Response(int status, String body, String contentType, Map<String, String> headers, List<String> setCookies) {}

  /**
   * The bridge endpoint.
   *
   * @param method the request method
   * @param bridgeHeader the {@code x-zevauth-bridge} header, or null
   * @param origin the {@code Origin} header, or null
   * @param requestOrigin this server's own origin, e.g. {@code https://app.example.com}
   * @param body the raw request body
   */
  public Response handle(String method, String bridgeHeader, String origin, String requestOrigin, byte[] body) {
    if (!"POST".equals(method)) {
      return json(405, error("method_not_allowed", "The session bridge accepts POST only."), Map.of("Allow", "POST"), List.of());
    }
    if (!"1".equals(bridgeHeader)) {
      return json(403, error("bridge_header_missing",
          "Send the " + BRIDGE_HEADER + ": 1 header. The ZevAuth browser SDK does this for you."), Map.of(), List.of());
    }
    List<String> allowed = allowedOrigins.isEmpty() ? List.of(String.valueOf(requestOrigin)) : allowedOrigins;
    if (origin != null && !origin.isEmpty() && !allowed.contains(origin)) {
      return json(403, error("bridge_origin_not_allowed", origin + " may not post sessions here. Add it to allowedOrigins."),
          Map.of(), List.of());
    }

    Object token;
    try {
      Map<?, ?> parsed = Json.MAPPER.readValue(body == null ? new byte[0] : body, Map.class);
      token = parsed.get("token");
    } catch (Exception e) {
      return json(400, error("invalid_request", "Expected a JSON body: { \"token\": string | null }."), Map.of(), List.of());
    }

    if (token == null || "".equals(token)) {
      return new Response(204, null, null, Map.of("Cache-Control", "no-store"), clearCookies());
    }
    if (!(token instanceof String)) {
      return json(400, error("invalid_request", "`token` must be a string or null."), Map.of(), List.of());
    }

    ZevAuthClaims claims;
    try {
      claims = verifier.verify((String) token);
    } catch (VerifyException e) {
      // A refused token also ends whatever was there, so a stale cookie
      // never outlives a refusal.
      Map<String, Object> err = new LinkedHashMap<>();
      err.put("code", AuthRefusal.UNAUTHORIZED);
      err.put("message", "That session token was refused.");
      err.put("reason", e.getCode());
      return json(401, Map.of("error", err), Map.of(), clearCookies());
    }

    long now = verifier.clock().instant().getEpochSecond();
    long maxAge = Math.max(0, claims.getExpiresAt() - now);
    List<String> cookies = new ArrayList<>();
    // The access token, until it expires. Never the refresh token.
    cookies.add(cookie(sessionCookieName(), (String) token, maxAge));
    cookies.add(cookie(clientCookieName(), "1", CLIENT_COOKIE_MAX_AGE));
    return new Response(204, null, null, Map.of("Cache-Control", "no-store"), cookies);
  }

  /** An {@link Auth} plus whether the browser should refresh the cookie. */
  public record BridgedAuth(Auth auth, boolean needsHandshake) {}

  /** Reads the Authorization header, then the session cookie. Never throws for a bad token. */
  public BridgedAuth read(String authorizationHeader, Map<String, String> cookies) {
    String header = Bearer.from(authorizationHeader);
    Map<String, String> jar = cookies == null ? Map.of() : cookies;
    String token = header != null ? header : jar.get(sessionCookieName());
    boolean hasClient = "1".equals(jar.get(clientCookieName()));

    if (token == null || token.isEmpty()) {
      return new BridgedAuth(Auth.signedOut(), header == null && hasClient);
    }
    try {
      return new BridgedAuth(Auth.from(verifier.verify(token)), false);
    } catch (VerifyException e) {
      boolean expired = VerifyException.TOKEN_EXPIRED.equals(e.getCode());
      return new BridgedAuth(Auth.signedOut(), header == null && (expired || hasClient));
    }
  }

  /** The result of {@link #authenticate}: the Auth, and a response to send instead of the page when non-null. */
  public record Outcome(Auth auth, Response handshake) {}

  /**
   * Reads the request and decides whether the browser must refresh the
   * cookie first: a page navigation is redirected to the handshake,
   * anything else gets 401 {@code session_refresh_required}.
   *
   * @param pathAndQuery the request's path and query, e.g. {@code /dashboard?tab=2}
   */
  public Outcome authenticate(String method, String accept, String pathAndQuery, String authorizationHeader,
      Map<String, String> cookies) {
    BridgedAuth read = read(authorizationHeader, cookies);
    if (!read.needsHandshake()) return new Outcome(read.auth(), null);

    // Back from a handshake and still no session: render signed out.
    // This is the loop guard.
    if (queryHas(pathAndQuery, HANDSHAKE_MARKER)) return new Outcome(read.auth(), null);

    boolean navigation = ("GET".equals(method) || "HEAD".equals(method)) && accept != null && accept.contains("text/html");
    if (!navigation) {
      return new Outcome(read.auth(), json(401, error("session_refresh_required",
          "The session cookie expired. Send the SDK token in Authorization, or reload the page."), Map.of(), List.of()));
    }
    String location = handshakePath + "?redirect_url=" + ZevAuthClient.enc(pathAndQuery == null ? "/" : pathAndQuery);
    return new Outcome(read.auth(),
        new Response(302, null, null, Map.of("Location", location, "Cache-Control", "no-store"), List.of()));
  }

  /** Options for {@link #handshakePage}. */
  public record HandshakeOptions(String publishableKey, String bridgePath, String apiUrl, String uiScriptUrl) {
    public HandshakeOptions(String publishableKey, String bridgePath) {
      this(publishableKey, bridgePath, null, null);
    }
  }

  /**
   * The handshake page: plain HTML that lets the browser SDK refresh the
   * session, posts it to the bridge, and returns to {@code redirectUrl}
   * with the loop-guard marker. A redirect that is not a same-site path
   * returns to {@code /} (open-redirect guard).
   */
  public static Response handshakePage(String redirectUrl, HandshakeOptions options) {
    String requested = redirectUrl == null ? "/" : redirectUrl;
    // //evil.example and /\evil.example are absolute URLs to a browser.
    if (!requested.startsWith("/") || requested.startsWith("//") || requested.startsWith("/\\")) requested = "/";
    String back = requested + (requested.contains("?") ? "&" : "?") + HANDSHAKE_MARKER + "=1";

    Map<String, Object> config = new LinkedHashMap<>();
    config.put("publishableKey", options.publishableKey());
    config.put("apiUrl", options.apiUrl());
    config.put("bridge", options.bridgePath());
    config.put("back", back);
    // Escape < so nothing in the config can close the script element.
    String json = Json.write(config).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026");
    String script = options.uiScriptUrl() == null ? DEFAULT_UI_SCRIPT_URL : options.uiScriptUrl();

    String html = "<!doctype html><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noindex\"><title>Signing in…</title>\n"
        + "<script src=\"" + escapeAttribute(script) + "\"></script>\n"
        + "<script>\n"
        + "(async function () {\n"
        + "  var c = " + json + ";\n"
        + "  try {\n"
        + "    window.ZevAuthUI.init({ publishableKey: c.publishableKey, apiUrl: c.apiUrl || undefined, sessionBridge: { url: c.bridge } });\n"
        + "    var client = window.ZevAuthUI.getClient();\n"
        + "    await client.load();\n"
        + "    await client.syncSessionBridge();\n"
        + "  } catch (e) {}\n"
        + "  location.replace(c.back);\n"
        + "})();\n"
        + "</script>";
    return new Response(200, html, "text/html; charset=utf-8",
        Map.of("Cache-Control", "no-store", "Referrer-Policy", "same-origin"), List.of());
  }

  /** Parses a {@code Cookie} header into name → value. */
  public static Map<String, String> parseCookies(String header) {
    Map<String, String> out = new LinkedHashMap<>();
    if (header == null) return out;
    for (String part : header.split(";")) {
      int eq = part.indexOf('=');
      if (eq > 0) out.put(part.substring(0, eq).trim(), part.substring(eq + 1).trim());
    }
    return out;
  }

  private List<String> clearCookies() {
    return List.of(cookie(sessionCookieName(), "", 0), cookie(clientCookieName(), "", 0));
  }

  private String cookie(String name, String value, long maxAge) {
    StringBuilder sb = new StringBuilder(name).append('=').append(value)
        .append("; Path=/; Max-Age=").append(maxAge).append("; HttpOnly; SameSite=Lax");
    if (secure) sb.append("; Secure");
    if (cookieDomain != null) sb.append("; Domain=").append(cookieDomain);
    return sb.toString();
  }

  private static boolean queryHas(String pathAndQuery, String name) {
    if (pathAndQuery == null) return false;
    int q = pathAndQuery.indexOf('?');
    if (q < 0) return false;
    for (String pair : pathAndQuery.substring(q + 1).split("&")) {
      String key = pair.contains("=") ? pair.substring(0, pair.indexOf('=')) : pair;
      if (key.equals(name)) return true;
    }
    return false;
  }

  private static Map<String, Object> error(String code, String message) {
    Map<String, Object> err = new LinkedHashMap<>();
    err.put("code", code);
    err.put("message", message);
    return Map.of("error", err);
  }

  private static Response json(int status, Object body, Map<String, String> extra, List<String> cookies) {
    Map<String, String> headers = new LinkedHashMap<>(extra);
    headers.put("Cache-Control", "no-store");
    return new Response(status, Json.write(body), "application/json", headers, cookies);
  }

  private static String escapeAttribute(String value) {
    return value.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;");
  }

  static byte[] utf8(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  /** Configures a {@link SessionBridge}. */
  public static final class Builder {
    private final ZevAuthVerifier verifier;
    private List<String> allowedOrigins = List.of();
    private String cookieDomain;
    private boolean secure = true;
    private String handshakePath = DEFAULT_HANDSHAKE_PATH;

    private Builder(ZevAuthVerifier verifier) {
      this.verifier = verifier;
    }

    /** Defaults to the request's own origin. List every page origin when using a cookie domain. */
    public Builder allowedOrigins(List<String> origins) { this.allowedOrigins = Objects.requireNonNull(origins); return this; }
    /** Shares the cookies with subdomains (__Secure- names). */
    public Builder cookieDomain(String domain) { this.cookieDomain = domain == null || domain.isEmpty() ? null : domain; return this; }
    /** false drops Secure and the cookie prefixes: plain-http local development only. */
    public Builder secure(boolean secure) { this.secure = secure; return this; }
    public Builder handshakePath(String path) { this.handshakePath = Objects.requireNonNull(path); return this; }

    public SessionBridge build() {
      return new SessionBridge(this);
    }
  }
}
