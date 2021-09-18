package com.cross.solutions.uaa.core;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class DefaultAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
  private static final StringKeyGenerator COOKIE_NAME_GENERATOR =
      new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding());

  @Autowired private JwtEncoder jwtEncoder;
  @Autowired private JwtDecoder jwtDecoder;

  //  private final JwtSettings jwtSettings;
  //  private final JwtTokenFactory tokenFactory;
  //  private final InvalidLoginAttemptsService invalidLoginAttemptsService;

  //  @Autowired
  //  public DefaultAuthenticationSuccessHandler(final JwtSettings jwtSettings,
  //      final JwtTokenFactory tokenFactory,
  //      final InvalidLoginAttemptsService invalidLoginAttemptsService) {
  //    this.jwtSettings = jwtSettings;
  //    this.tokenFactory = tokenFactory;
  //    this.invalidLoginAttemptsService = invalidLoginAttemptsService;
  //  }

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {

    AuthenticationUser authenticationUser = (AuthenticationUser) authentication.getPrincipal();

    JoseHeader headers = JwtUtils.headers().build();
    Set<String> authorities =
        authenticationUser.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toSet());
    JwtClaimsSet claims =
        JwtUtils.accessTokenClaims(null, null, authenticationUser.getUsername(), authorities)
            .build();

    String accessToken = jwtEncoder.encode(headers, claims).getTokenValue();

    Map<String, Map<String, String>> accounts = retrieveAccounts(request);

    // Reuse old "code" in case authentication user existed in "accounts".
    String code =
        accounts.entrySet().stream()
            .filter(
                account ->
                    account.getValue().get("username").equals(authenticationUser.getUsername()))
            .map(Entry::getKey)
            .findFirst()
            .orElse(null);

    if (code == null) {
      code = randomCookieName(accounts);
    }

    Map<String, String> account = new HashMap<>();
    account.put("username", authenticationUser.getUsername());
    account.put("firstname", authenticationUser.getFirstname());
    account.put("lastname", authenticationUser.getLastname());
    accounts.put(code, account);

    headers = JwtUtils.headers().build();
    claims =
        JwtUtils.accountChooserTokenClaims(null, null, authenticationUser.getUsername(), accounts)
            .build();

    String accountChooserToken = jwtEncoder.encode(headers, claims).getTokenValue();

    response.addHeader("Account-Chooser", accountChooserToken);
    response.addHeader("Auth-Account", code + " " + accessToken);

    //    this.invalidLoginAttemptsService.loginSucceeded(authenticationUser.getUsername());
  }

  private Map<String, Map<String, String>> retrieveAccounts(HttpServletRequest request) {
    Map<String, Map<String, String>> accounts = new HashMap<>();
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return accounts;
    }

    String token =
        Arrays.stream(cookies)
            .filter(c -> c.getName().equals("ACCOUNT_CHOOSER"))
            .findFirst()
            .map(Cookie::getValue)
            .orElse(null);

    if (!StringUtils.hasText(token)) {
      return accounts;
    }

    try {
      accounts = jwtDecoder.decode(token).<Map<String, Map<String, String>>>getClaim("accounts");

      // remove unknown account_code inside ACCOUNT_CHOOSER
      accounts
          .keySet()
          .removeIf(
              code -> Arrays.stream(cookies).noneMatch(cookie -> code.equals(cookie.getName())));
    } catch (JwtException expected) {
      // expected
    }

    return accounts;
  }

  private String randomCookieName(Map<String, Map<String, String>> accounts) {
    String randomName = null;
    do {
      randomName = COOKIE_NAME_GENERATOR.generateKey().substring(0, 5);
    } while (accounts.containsKey(randomName));
    return randomName;
  }
}
