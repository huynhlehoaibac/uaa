package com.cross.solutions.uaa.core;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class CustomUsernamePasswordAuthenticationFilter
    extends UsernamePasswordAuthenticationFilter {

  private AuthenticationSuccessHandler successHandler = new DefaultAuthenticationSuccessHandler();

  //	private AuthenticationFailureHandler failureHandler = new
  // DefaultAuthenticationFailureHandler();

  /**
   * Creates a new instance with a {@link RequestMatcher} and an {@link AuthenticationManager}
   *
   * @param requiresAuthenticationRequestMatcher the {@link RequestMatcher} used to determine if
   *     authentication is required. Cannot be null.
   * @param authenticationManager the {@link AuthenticationManager} used to authenticate an {@link
   *     Authentication} object. Cannot be null.
   */
  /** @param defaultFilterProcessesUrl the default value for <tt>filterProcessesUrl</tt>. */
  protected CustomUsernamePasswordAuthenticationFilter(
      String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
    setFilterProcessesUrl(defaultFilterProcessesUrl);
    setAuthenticationManager(authenticationManager);
    setAuthenticationSuccessHandler(successHandler);
    //    setAuthenticationFailureHandler(failureHandler);
  }
  
  @Override
	protected String obtainUsername(HttpServletRequest request) {
		return request.getParameter(this.getUsernameParameter());
	}
}
