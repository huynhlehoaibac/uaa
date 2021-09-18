package com.cross.solutions.uaa.core;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {
  //  private JwtSettings jwtSettings;
  private UserDetailsService userDetailsService;
//  private UserDetailsChecker authenticationChecks;
  
  @Autowired private JwtDecoder jwtDecoder;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    RawJwtToken rawAccessToken = (RawJwtToken) authentication.getCredentials();
    
    Jwt jwt = jwtDecoder.decode(rawAccessToken.getToken());

//    Jws<Claims> jwsClaims = rawAccessToken.parseClaims(jwtSettings.getTokenSigningKey());
//    Claims claims = jwsClaims.getBody();

    String username = jwt.getSubject();

    AuthenticationUser authenticationUser =
        (AuthenticationUser) userDetailsService.loadUserByUsername(username);
//    authenticationChecks.check(authenticationUser);

    return new JwtAuthenticationToken(authenticationUser, authenticationUser.getAuthorities());
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return JwtAuthenticationToken.class.isAssignableFrom(authentication);
  }

//  @Autowired
//  public void setJwtSettings(JwtSettings jwtSettings) {
//    this.jwtSettings = jwtSettings;
//  }

  @Autowired
  public void setUserDetailsService(UserDetailsService userDetailsService) {
    this.userDetailsService = userDetailsService;
  }

//  @Autowired
//  public void setAuthenticationChecks(UserDetailsChecker authenticationChecks) {
//    this.authenticationChecks = authenticationChecks;
//  }
}
