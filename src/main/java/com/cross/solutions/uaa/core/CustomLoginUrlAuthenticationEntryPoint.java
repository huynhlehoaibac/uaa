package com.cross.solutions.uaa.core;

import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

public class CustomLoginUrlAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

  public CustomLoginUrlAuthenticationEntryPoint(String loginFormUrl) {
    super(loginFormUrl);
  }

  /**
   * Add the original request URL to the login form URL so that it can be redirected back after
   * successful authentication.
   *
   * @param request the request
   * @param response the response
   * @param exception the exception
   * @return the URL (cannot be null or empty; defaults to {@link #getLoginFormUrl()})
   */
  @Override
  protected String determineUrlToUseForThisRequest(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
    return UriComponentsBuilder.fromHttpUrl(getLoginFormUrl())
        .queryParam(
            "origin",
            UriUtils.encode(
                request.getRequestURL().toString() + "?" + request.getQueryString(),
                StandardCharsets.UTF_8))
        .toUriString();
  }
}
