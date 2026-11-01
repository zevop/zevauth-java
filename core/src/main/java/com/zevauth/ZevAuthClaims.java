package com.zevauth;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * A verified token's claims (contract §1.1). Absent claims are absent:
 * optional strings are {@code null}, optional lists are empty.
 */
public final class ZevAuthClaims {
  private final Map<String, Object> raw;

  ZevAuthClaims(Map<String, Object> raw) {
    this.raw = Collections.unmodifiableMap(raw);
  }

  /** The user's public id. */
  public String getSubject() { return string("sub"); }
  public String getSessionId() { return string("sid"); }
  public String getIssuer() { return string("iss"); }
  public String getTokenId() { return string("jti"); }
  public long getIssuedAt() { return number("iat"); }
  public long getNotBefore() { return number("nbf"); }
  public long getExpiresAt() { return number("exp"); }
  public String getEmail() { return string("email"); }
  public boolean isEmailVerified() { return Boolean.TRUE.equals(raw.get("email_verified")); }
  public String getName() { return string("name"); }
  public String getPicture() { return string("picture"); }

  @SuppressWarnings("unchecked")
  public Map<String, Object> getPublicMetadata() {
    Object value = raw.get("public_metadata");
    return value instanceof Map ? (Map<String, Object>) value : Collections.emptyMap();
  }

  public String getOrgId() { return string("org_id"); }
  public String getOrgSlug() { return string("org_slug"); }
  public String getOrgName() { return string("org_name"); }
  public String getOrgRole() { return string("org_role"); }
  public List<String> getOrgPermissions() { return list("org_permissions"); }
  public List<String> getPendingTasks() { return list("pending_tasks"); }
  public List<String> getAmr() { return list("amr"); }

  /** Every claim as decoded, including ones this version does not know. */
  public Map<String, Object> asMap() {
    return raw;
  }

  private String string(String name) {
    Object value = raw.get(name);
    return value instanceof String ? (String) value : null;
  }

  private long number(String name) {
    Object value = raw.get(name);
    return value instanceof Number ? ((Number) value).longValue() : 0L;
  }

  @SuppressWarnings("unchecked")
  private List<String> list(String name) {
    Object value = raw.get(name);
    return value instanceof List ? Collections.unmodifiableList((List<String>) value) : Collections.emptyList();
  }

  /** Throws malformed_token when a known claim has the wrong type. */
  static void checkTypes(Map<String, Object> raw) throws VerifyException {
    for (String name : List.of("iss", "sub")) {
      if (!(raw.get(name) instanceof String)) {
        throw new VerifyException(VerifyException.MALFORMED_TOKEN, "claim " + name + " is missing or not a string");
      }
    }
    for (String name : List.of("sid", "jti", "email", "name", "picture", "org_id", "org_slug", "org_name", "org_role")) {
      if (raw.containsKey(name) && !(raw.get(name) instanceof String)) {
        throw new VerifyException(VerifyException.MALFORMED_TOKEN, "claim " + name + " is not a string");
      }
    }
    for (String name : List.of("iat", "nbf", "exp")) {
      if (raw.containsKey(name) && !(raw.get(name) instanceof Number)) {
        throw new VerifyException(VerifyException.MALFORMED_TOKEN, "claim " + name + " is not a number");
      }
    }
    for (String name : List.of("org_permissions", "pending_tasks", "amr")) {
      Object value = raw.get(name);
      if (value == null && !raw.containsKey(name)) continue;
      if (!(value instanceof List) || !((List<?>) value).stream().allMatch(String.class::isInstance)) {
        throw new VerifyException(VerifyException.MALFORMED_TOKEN, "claim " + name + " is not a list of strings");
      }
    }
    Object aud = raw.get("aud");
    if (aud != null && !(aud instanceof String) && !(aud instanceof List)) {
      throw new VerifyException(VerifyException.MALFORMED_TOKEN, "claim aud has the wrong type");
    }
    if (raw.containsKey("email_verified") && !(raw.get("email_verified") instanceof Boolean)) {
      throw new VerifyException(VerifyException.MALFORMED_TOKEN, "claim email_verified is not a boolean");
    }
  }
}
