package com.cross.solutions.uaa.core;

import org.springframework.security.core.AuthenticationException;

public class ExpiredJwtException extends AuthenticationException {
  private static final long serialVersionUID = 1L;

  private final JwtToken token;

  public ExpiredJwtException(String msg) {
    super(msg);
    this.token = null;
  }

  public ExpiredJwtException(JwtToken token, String msg, Throwable t) {
    super(msg, t);
    this.token = token;
  }

  public String token() {
    return token.getToken();
  }
}
