package com.zevauth.servlet;

import com.zevauth.SessionBridge;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/** Serves the handshake page. Map it at the bridge's handshake path. */
public class HandshakeServlet extends HttpServlet {
  private static final long serialVersionUID = 1L;

  private final transient SessionBridge.HandshakeOptions options;

  public HandshakeServlet(SessionBridge.HandshakeOptions options) {
    this.options = options;
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    ServletSupport.write(response, SessionBridge.handshakePage(request.getParameter("redirect_url"), options));
  }
}
