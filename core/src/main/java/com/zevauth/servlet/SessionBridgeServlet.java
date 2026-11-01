package com.zevauth.servlet;

import com.zevauth.SessionBridge;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * The bridge endpoint. Map it at the URL you give the browser SDK's
 * {@code sessionBridge} option, e.g. {@code /zevauth/bridge}.
 */
public class SessionBridgeServlet extends HttpServlet {
  private static final long serialVersionUID = 1L;

  private final transient SessionBridge bridge;

  public SessionBridgeServlet(SessionBridge bridge) {
    this.bridge = bridge;
  }

  @Override
  protected void service(HttpServletRequest request, HttpServletResponse response) throws IOException {
    byte[] body = "POST".equals(request.getMethod()) ? request.getInputStream().readNBytes(64 * 1024) : new byte[0];
    ServletSupport.write(response, bridge.handle(request.getMethod(), request.getHeader(SessionBridge.BRIDGE_HEADER),
        request.getHeader("Origin"), ServletSupport.origin(request), body));
  }
}
