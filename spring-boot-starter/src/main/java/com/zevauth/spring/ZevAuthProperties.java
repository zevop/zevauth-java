package com.zevauth.spring;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** {@code zevauth.*} settings. */
@ConfigurationProperties(prefix = "zevauth")
public class ZevAuthProperties {
  /** The environment whose tokens are accepted: env_test_… or env_live_…. */
  private String environmentId;
  /** Defaults to https://api.zevauth.net. */
  private String apiUrl = "https://api.zevauth.net";
  /** Secret key (sk_…) for the backend API client. Keep it out of source control. */
  private String secretKey;
  /** Publishable key (pk_…), used by the session bridge's handshake page. */
  private String publishableKey;
  /** Signing secret (whsec_…) for webhook verification. */
  private String webhookSecret;
  /** A local key set instead of fetching one: the issuer it signs for. Tests and air-gapped servers. */
  private String issuer;
  /** A local key set instead of fetching one: the JWKS JSON. */
  private String jwks;

  private final Bridge bridge = new Bridge();

  /** The session bridge, for server-rendered pages. */
  public static class Bridge {
    /** Serve the bridge endpoint and handshake page, and read the session cookie. */
    private boolean enabled;
    /** Where the browser SDK posts its token: the sessionBridge url. */
    private String path = "/zevauth/bridge";
    private String handshakePath = "/zevauth/handshake";
    /** Origins that may post to the bridge. Defaults to the request's own origin. */
    private List<String> allowedOrigins = new ArrayList<>();
    /** Share the cookies with subdomains. */
    private String cookieDomain;
    /** false drops Secure and the cookie prefixes: plain-http local development only. */
    private boolean secure = true;
    /** Serve your own copy of @zevauth/ui on the handshake page, e.g. under a strict CSP. */
    private String uiScriptUrl;

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }
    public String getHandshakePath() { return handshakePath; }
    public void setHandshakePath(String handshakePath) { this.handshakePath = handshakePath; }
    public List<String> getAllowedOrigins() { return allowedOrigins; }
    public void setAllowedOrigins(List<String> allowedOrigins) { this.allowedOrigins = allowedOrigins; }
    public String getCookieDomain() { return cookieDomain; }
    public void setCookieDomain(String cookieDomain) { this.cookieDomain = cookieDomain; }
    public boolean isSecure() { return secure; }
    public void setSecure(boolean secure) { this.secure = secure; }
    public String getUiScriptUrl() { return uiScriptUrl; }
    public void setUiScriptUrl(String uiScriptUrl) { this.uiScriptUrl = uiScriptUrl; }
  }

  public String getEnvironmentId() { return environmentId; }
  public void setEnvironmentId(String environmentId) { this.environmentId = environmentId; }
  public String getApiUrl() { return apiUrl; }
  public void setApiUrl(String apiUrl) { this.apiUrl = apiUrl; }
  public String getSecretKey() { return secretKey; }
  public void setSecretKey(String secretKey) { this.secretKey = secretKey; }
  public String getPublishableKey() { return publishableKey; }
  public void setPublishableKey(String publishableKey) { this.publishableKey = publishableKey; }
  public String getWebhookSecret() { return webhookSecret; }
  public void setWebhookSecret(String webhookSecret) { this.webhookSecret = webhookSecret; }
  public String getIssuer() { return issuer; }
  public void setIssuer(String issuer) { this.issuer = issuer; }
  public String getJwks() { return jwks; }
  public void setJwks(String jwks) { this.jwks = jwks; }
  public Bridge getBridge() { return bridge; }
}
