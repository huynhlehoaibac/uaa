package com.cross.solutions.uaa.core;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
  private static final long serialVersionUID = -3918695958094213608L;

  private RawJwtToken rawJwtToken;
  private AuthenticationUser authenticationUser;

  public JwtAuthenticationToken(RawJwtToken unsafeToken) {
    super(null);
    this.rawJwtToken = unsafeToken;
    this.setAuthenticated(false);
  }

  public JwtAuthenticationToken(
      AuthenticationUser authenticationUser, Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    this.eraseCredentials();
    this.authenticationUser = authenticationUser;
    super.setAuthenticated(true);
  }

  @Override
  public void setAuthenticated(boolean authenticated) {
    if (authenticated) {
      throw new IllegalArgumentException(
          "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
    }
    super.setAuthenticated(false);
  }

  @Override
  public Object getCredentials() {
    return rawJwtToken;
  }

  @Override
  public Object getPrincipal() {
    return authenticationUser;
  }

  @Override
  public void eraseCredentials() {
    super.eraseCredentials();
    this.rawJwtToken = null;
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof JwtAuthenticationToken)) {
      return false;
    }

    JwtAuthenticationToken test = (JwtAuthenticationToken) obj;

    if (!super.equals(obj)) {
      return false;
    }

    if ((this.getCredentials() == null) && (test.getCredentials() != null)) {
      return false;
    }
    if ((this.getCredentials() != null) && (test.getCredentials() == null)) {
      return false;
    }
    if ((this.getCredentials() != null) && (!this.getCredentials().equals(test.getCredentials()))) {
      return false;
    }

    if ((this.getPrincipal() == null) && (test.getPrincipal() != null)) {
      return false;
    }
    if ((this.getPrincipal() != null) && (test.getPrincipal() == null)) {
      return false;
    }

    return ((this.getPrincipal() != null) && (!this.getPrincipal().equals(test.getPrincipal())));
  }

  @Override
  public int hashCode() {
    int code = 31;

    if (this.getPrincipal() != null) {
      code ^= this.getPrincipal().hashCode();
    }

    if (this.getCredentials() != null) {
      code ^= this.getCredentials().hashCode();
    }

    return code;
  }
}
