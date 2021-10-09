package com.cross.solutions.uaa.core;

import javax.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

public interface TokenExtractor {
  Authentication extract(HttpServletRequest request);
}
