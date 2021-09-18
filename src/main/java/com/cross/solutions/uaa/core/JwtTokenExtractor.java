package com.cross.solutions.uaa.core;

import javax.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtTokenExtractor implements TokenExtractor {
  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String AUTHORIZATION_SCHEMA = "Bearer ";

  @Override
  public Authentication extract(HttpServletRequest request) {
    String authorizationValue = request.getHeader(AUTHORIZATION_HEADER);

    if (!StringUtils.hasText(authorizationValue)) {
      log.debug("Authorization header cannot be empty");
      throw new AuthenticationServiceException("Authorization header cannot be empty");
    }

    if (!authorizationValue.startsWith(AUTHORIZATION_SCHEMA)) {
      log.debug("Invalid authorization header size");
      throw new AuthenticationServiceException("Invalid authorization header size");
    }

    String token = authorizationValue.substring(AUTHORIZATION_SCHEMA.length());
    RawJwtToken rawJwtToken = new RawJwtToken(token);
    return new JwtAuthenticationToken(rawJwtToken);
  }
}
