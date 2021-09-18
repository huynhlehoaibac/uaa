package com.cross.solutions.uaa.core;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class DefaultAuthenticationFailureHandler implements AuthenticationFailureHandler {
//  private String usernameParameter = RestLoginProcessingFilter.SPRING_SECURITY_FORM_USERNAME_KEY;

  private final ObjectMapper mapper;
//  private final InvalidLoginAttemptsService invalidLoginAttemptsService;

  @Autowired
  public DefaultAuthenticationFailureHandler(ObjectMapper mapper
//      , final InvalidLoginAttemptsService invalidLoginAttemptsService
      ) {
    this.mapper = mapper;
//    this.invalidLoginAttemptsService = invalidLoginAttemptsService;
  }

  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException exception) throws IOException, ServletException {
    log.debug("Authentication failed: {}", exception.getMessage());

    response.setStatus(HttpStatus.UNAUTHORIZED.value());
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//    ErrorResponse errorResponse = ErrorResponse.builder()
//      .status(HttpStatus.UNAUTHORIZED)
//      .error("Unauthorized")
//      .message(exception.getMessage())
//      .path(request.getRequestURI().substring(request.getContextPath().length()))
//      .build();
//
//    mapper.writeValue(response.getWriter(), errorResponse);
//
//    if (exception instanceof BadCredentialsException) {
//      invalidLoginAttemptsService.loginFailed(request.getParameter(usernameParameter));
//    }
  }
}
