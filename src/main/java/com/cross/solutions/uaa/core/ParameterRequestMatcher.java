package com.cross.solutions.uaa.core;

import javax.servlet.http.HttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class ParameterRequestMatcher implements RequestMatcher {
  private String name;

  public ParameterRequestMatcher(String name) {
    Assert.notNull(name, "parameter cannot be null");
    this.name = name;
  }

  @Override
  public boolean matches(HttpServletRequest request) {
    return StringUtils.hasText(request.getParameter(name));
  }
}
