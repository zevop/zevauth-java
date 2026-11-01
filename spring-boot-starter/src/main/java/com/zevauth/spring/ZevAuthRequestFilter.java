package com.zevauth.spring;

import com.zevauth.Auth;
import com.zevauth.SessionBridge;
import com.zevauth.ZevAuthVerifier;
import com.zevauth.servlet.ServletSupport;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.function.Consumer;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Reads who each request is from and stores it for controllers, the
 * {@code Auth} argument and {@code @RequireAuth}. With the bridge enabled it
 * also serves the bridge endpoint and handshake page, reads the session
 * cookie, and runs the handshake when the cookie needs refreshing.
 *
 * <p>Runs once per request. To use ZevAuth in Spring Security URL rules,
 * add this bean to your chain before the authorization filter:
 * {@code http.addFilterBefore(zevAuthRequestFilter, AuthorizationFilter.class)}.
 */
public class ZevAuthRequestFilter extends OncePerRequestFilter {
  private final ZevAuthVerifier verifier;
  private final SessionBridge bridge;
  private final String bridgePath;
  private final SessionBridge.HandshakeOptions handshake;
  private final Consumer<Auth> securityContext;

  /**
   * @param bridge null without the session bridge
   * @param securityContext null without Spring Security
   */
  public ZevAuthRequestFilter(ZevAuthVerifier verifier, SessionBridge bridge, String bridgePath,
      SessionBridge.HandshakeOptions handshake, Consumer<Auth> securityContext) {
    this.verifier = verifier;
    this.bridge = bridge;
    this.bridgePath = bridgePath;
    this.handshake = handshake;
    this.securityContext = securityContext;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String path = request.getRequestURI().substring(request.getContextPath().length());

    if (bridge != null && path.equals(bridgePath)) {
      byte[] body = "POST".equals(request.getMethod()) ? request.getInputStream().readNBytes(64 * 1024) : new byte[0];
      ServletSupport.write(response, bridge.handle(request.getMethod(), request.getHeader(SessionBridge.BRIDGE_HEADER),
          request.getHeader("Origin"), ServletSupport.origin(request), body));
      return;
    }
    if (bridge != null && handshake != null && path.equals(bridge.getHandshakePath()) && "GET".equals(request.getMethod())) {
      ServletSupport.write(response, SessionBridge.handshakePage(request.getParameter("redirect_url"), handshake));
      return;
    }

    Auth auth;
    String authorization = request.getHeader("Authorization");
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

    request.setAttribute(ServletSupport.AUTH_ATTRIBUTE, auth);
    if (securityContext != null && auth.isSignedIn()) securityContext.accept(auth);
    chain.doFilter(request, response);
  }
}
