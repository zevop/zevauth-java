package com.zevauth.spring;

import com.zevauth.Auth;
import java.util.ArrayList;
import java.util.List;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * A ZevAuth session as a Spring Security {@code Authentication}. The
 * principal is the user id; the authorities are the active organization's
 * role and permissions, so {@code hasAuthority('org:members:manage')}
 * works. Only loaded when Spring Security is on the classpath.
 */
public class ZevAuthAuthentication extends AbstractAuthenticationToken {
  private static final long serialVersionUID = 1L;

  private final transient Auth auth;

  public ZevAuthAuthentication(Auth auth) {
    super(authorities(auth));
    this.auth = auth;
    setAuthenticated(auth.isSignedIn());
  }

  /** The full ZevAuth view of the request. */
  public Auth getAuth() {
    return auth;
  }

  @Override
  public Object getCredentials() {
    return "";
  }

  @Override
  public Object getPrincipal() {
    return auth.getUserId();
  }

  private static List<GrantedAuthority> authorities(Auth auth) {
    List<GrantedAuthority> out = new ArrayList<>();
    if (auth.getOrganizationRole() != null) out.add(new SimpleGrantedAuthority(auth.getOrganizationRole()));
    if (auth.getClaims() != null) auth.getClaims().getOrgPermissions().forEach(p -> out.add(new SimpleGrantedAuthority(p)));
    return out;
  }

  /** Sets this request's security context, leaving any existing authentication alone. */
  static void install(Auth auth) {
    SecurityContext current = SecurityContextHolder.getContext();
    if (current.getAuthentication() != null && current.getAuthentication().isAuthenticated()
        && !(current.getAuthentication() instanceof org.springframework.security.authentication.AnonymousAuthenticationToken)) {
      return;
    }
    SecurityContext context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(new ZevAuthAuthentication(auth));
    SecurityContextHolder.setContext(context);
  }
}
