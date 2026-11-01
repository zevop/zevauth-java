package com.zevauth.servlet;

import com.zevauth.Auth;
import com.zevauth.SessionBridge;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/** Helpers shared by the servlet adapters. */
public final class ServletSupport {
  /** The request attribute {@link ZevAuthFilter} stores the {@link Auth} under. */
  public static final String AUTH_ATTRIBUTE = Auth.class.getName();

  private ServletSupport() {}

  /** The Auth {@link ZevAuthFilter} stored, or signed out when it did not run. */
  public static Auth getAuth(HttpServletRequest request) {
    Object auth = request.getAttribute(AUTH_ATTRIBUTE);
    return auth instanceof Auth ? (Auth) auth : Auth.signedOut();
  }

  /** This server's own origin, honouring X-Forwarded-Proto/Host from a proxy you trust. */
  public static String origin(HttpServletRequest request) {
    String scheme = request.getHeader("X-Forwarded-Proto");
    if (scheme == null) scheme = request.getScheme();
    String host = request.getHeader("X-Forwarded-Host");
    if (host == null) host = request.getHeader("Host");
    if (host == null) {
      int port = request.getServerPort();
      boolean defaultPort = ("https".equals(scheme) && port == 443) || ("http".equals(scheme) && port == 80);
      host = request.getServerName() + (defaultPort ? "" : ":" + port);
    }
    return scheme + "://" + host;
  }

  public static String pathAndQuery(HttpServletRequest request) {
    String query = request.getQueryString();
    return request.getRequestURI() + (query == null ? "" : "?" + query);
  }

  public static Map<String, String> cookies(HttpServletRequest request) {
    Map<String, String> out = new LinkedHashMap<>();
    Cookie[] cookies = request.getCookies();
    if (cookies != null) for (Cookie c : cookies) out.putIfAbsent(c.getName(), c.getValue());
    return out;
  }

  /** Writes a bridge response, cookies included. */
  public static void write(HttpServletResponse response, SessionBridge.Response r) throws IOException {
    response.setStatus(r.status());
    r.headers().forEach(response::setHeader);
    for (String cookie : r.setCookies()) response.addHeader("Set-Cookie", cookie);
    if (r.body() != null) {
      response.setContentType(r.contentType());
      response.setCharacterEncoding(StandardCharsets.UTF_8.name());
      response.getOutputStream().write(r.body().getBytes(StandardCharsets.UTF_8));
    }
  }
}
