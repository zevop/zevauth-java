package com.zevauth;

import java.util.List;

/**
 * Who a request is from (contract §2.1). Signed out when no valid session
 * came with it.
 */
public final class Auth {
  private static final Auth SIGNED_OUT = new Auth(null);

  private final ZevAuthClaims claims;

  private Auth(ZevAuthClaims claims) {
    this.claims = claims;
  }

  public static Auth signedOut() {
    return SIGNED_OUT;
  }

  public static Auth from(ZevAuthClaims claims) {
    return new Auth(claims);
  }

  public boolean isSignedIn() { return claims != null; }
  public String getUserId() { return claims == null ? null : claims.getSubject(); }
  public String getSessionId() { return claims == null ? null : claims.getSessionId(); }
  public String getOrganizationId() { return claims == null ? null : claims.getOrgId(); }
  public String getOrganizationRole() { return claims == null ? null : claims.getOrgRole(); }
  /** All verified claims, or null when signed out. */
  public ZevAuthClaims getClaims() { return claims; }
  public List<String> getPendingTasks() { return claims == null ? List.of() : claims.getPendingTasks(); }
  public boolean isMfaVerified() { return claims != null && claims.getAmr().contains("mfa"); }

  /**
   * Whether the active organization grants every given role and
   * permission. False with no active organization, and false when both
   * are null.
   */
  public boolean has(String role, String permission) {
    if (claims == null || claims.getOrgId() == null) return false;
    if (role == null && permission == null) return false;
    if (role != null && !role.equals(claims.getOrgRole())) return false;
    return permission == null || claims.getOrgPermissions().contains(permission);
  }

  public boolean hasRole(String role) { return has(role, null); }
  public boolean hasPermission(String permission) { return has(null, permission); }

  /**
   * Applies the requireAuth rules in the contract's order.
   *
   * @throws AuthRefusal 401 unauthorized, 403 session_task_pending, or 403 mfa_required
   */
  public void require(RequireOptions options) throws AuthRefusal {
    RequireOptions o = options == null ? RequireOptions.DEFAULT : options;
    if (!isSignedIn()) {
      throw new AuthRefusal(401, AuthRefusal.UNAUTHORIZED, "Sign in to continue.", List.of());
    }
    if (!getPendingTasks().isEmpty() && !o.allowPendingTasks()) {
      throw new AuthRefusal(403, AuthRefusal.SESSION_TASK_PENDING, "Finish setting up your account to continue.", getPendingTasks());
    }
    if (o.requireMfa() && !isMfaVerified()) {
      throw new AuthRefusal(403, AuthRefusal.MFA_REQUIRED, "Two-step verification is required.", List.of());
    }
  }
}
