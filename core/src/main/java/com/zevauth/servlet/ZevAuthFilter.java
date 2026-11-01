package com.zevauth.servlet;

import com.zevauth.Auth;
import com.zevauth.AuthRefusal;
import com.zevauth.RequireOptions;
import com.zevauth.SessionBridge;
import com.zevauth.ZevAuthVerifier;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Reads who each request is from and stores it for
 * {@link ServletSupport#getAuth}. With a bridge it also reads the session
 * cookie and runs the handshake when the cookie needs refreshing. With
 * {@code require} it refuses like {@code requireAuth}.
 */
public class ZevAuthFilter implements Filter {
  private final ZevAuthVerifier verifier;
  private final SessionBridge bridge;
  private final RequireOptions require;

  /** Bearer tokens only; every request passes through. */
  public ZevAuthFilter(ZevAuthVerifier verifier) {
    this(verifier, null, null);
  }

  /**
   * @param bridge null for bearer tokens only
   * @param require null to let every request through and decide per handler
   */
  public ZevAuthFilter(ZevAuthVerifier verifier, SessionBridge bridge, RequireOptions require) {
    this.verifier = verifier;
    this.bridge = bridge;
    this.require = require;
  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;
    String authorization = request.getHeader("Authorization");

    Auth auth;
    if (bridge != null) {
      SessionBridge.Outcome outcome = bridge.authenticate(request.getMethod(), request.getHeader("Accept"),
          ServletSupport.pathAndQuery(request), authorization, ServletSupport.cookies(request));
      if (outcome.handshake() != null) {
        ServletSupport.write(response, outcome.handshake());
        return;
      }
      auth = outcome.auth();
    } else {
      auth = verifier.getAuth(authorization);
    }

    if (require != null) {
      try {
        auth.require(require);
      } catch (AuthRefusal refusal) {
        writeRefusal(response, refusal);
        return;
      }
    }
    request.setAttribute(ServletSupport.AUTH_ATTRIBUTE, auth);
    chain.doFilter(request, response);
  }

  /** Writes the shared error envelope with the refusal's status. */
  public static void writeRefusal(HttpServletResponse response, AuthRefusal refusal) throws IOException {
    response.setStatus(refusal.getStatus());
    response.setHeader("Cache-Control", "no-store");
    response.setContentType("application/json");
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    response.getOutputStream().write(refusal.toJson().getBytes(StandardCharsets.UTF_8));
  }
}
