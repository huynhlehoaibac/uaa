package com.cross.solutions.uaa.core;

import java.util.Arrays;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

public class AccountCodeTokenExtractor implements TokenExtractor {
  public static final String AUTHENTICATION_PARAMETER_NAME = "account_code";

  @Override
  public Authentication extract(HttpServletRequest request) {
    String token = null;
    String code = request.getParameter(AUTHENTICATION_PARAMETER_NAME);

    if (StringUtils.hasText(code) && request.getCookies() != null) {
      token =
          Arrays.stream(request.getCookies())
              .filter(c -> c.getName().equals(code))
              .findFirst()
              .map(Cookie::getValue)
              .orElse(null);
    }

    if (!StringUtils.hasText(token)) {
      throw new AuthenticationServiceException("Authentication parameter cannot be empty");
    }

    RawJwtToken rawAccessJwtToken = new RawJwtToken(token);
    return new JwtAuthenticationToken(rawAccessJwtToken);
  }
}
