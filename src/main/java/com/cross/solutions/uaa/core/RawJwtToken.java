package com.cross.solutions.uaa.core;

import org.springframework.security.authentication.BadCredentialsException;
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jws;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.MalformedJwtException;
//import io.jsonwebtoken.SignatureException;
//import io.jsonwebtoken.UnsupportedJwtException;

public class RawJwtToken implements JwtToken {
  private static final long serialVersionUID = 1L;

  private String token;

  public RawJwtToken(String token) {
    this.token = token;
  }

  /**
   * Parses and validates JWT Token signature.
   * 
   * @throws BadCredentialsException
   * @throws ExpiredJwtException
   * 
   */
//  public Jws<Claims> parseClaims(String signingKey) {
//    try {
//      return Jwts.parser().setSigningKey(signingKey).parseClaimsJws(token);
//    } catch (UnsupportedJwtException | MalformedJwtException | SignatureException
//        | IllegalArgumentException ex) {
//      throw new BadCredentialsException("Invalid JWT token", ex);
//    } catch (io.jsonwebtoken.ExpiredJwtException expiredEx) {
//      throw new ExpiredJwtException(this, "JWT Token expired", expiredEx);
//    }
//  }

  @Override
  public String getToken() {
    return token;
  }
}
