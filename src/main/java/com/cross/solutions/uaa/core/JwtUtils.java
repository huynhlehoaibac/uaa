package com.cross.solutions.uaa.core;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * Utility methods used by the {@link DefaultAuthenticationSuccessHandler}'s when issuing {@link
 * Jwt}'s.
 *
 * @author huynhlehoaibac
 * @since 0.0.1-SNAPSHOT
 * @see JwtUtils
 */
final class JwtUtils {

  private JwtUtils() {}

  static JoseHeader.Builder headers() {
    return JoseHeader.withAlgorithm(SignatureAlgorithm.RS256);
  }

  static JwtClaimsSet.Builder accessTokenClaims(
      RegisteredClient registeredClient,
      String issuer,
      String subject,
      Set<String> authorizedScopes) {

    Instant issuedAt = Instant.now();
    Instant expiresAt = issuedAt.plus(365, ChronoUnit.DAYS);
    //    Instant expiresAt =
    //    		issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());

    JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();
    if (StringUtils.hasText(issuer)) {
      claimsBuilder.issuer(issuer);
    }
    claimsBuilder
        .subject(subject)
        //        .audience(Collections.singletonList(registeredClient.getClientId()))
        .issuedAt(issuedAt)
        .expiresAt(expiresAt)
        .notBefore(issuedAt);
    if (!CollectionUtils.isEmpty(authorizedScopes)) {
      claimsBuilder.claim(OAuth2ParameterNames.SCOPE, authorizedScopes);
    }

    return claimsBuilder;
  }

  static JwtClaimsSet.Builder accountChooserTokenClaims(
      RegisteredClient registeredClient,
      String issuer,
      String subject,
      Map<String, Map<String, String>> accounts) {

    Instant issuedAt = Instant.now();
    Instant expiresAt = issuedAt.plus(365, ChronoUnit.DAYS);
    //    Instant expiresAt =
    //    		issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());

    JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder();
    if (StringUtils.hasText(issuer)) {
      claimsBuilder.issuer(issuer);
    }
    claimsBuilder
        .subject(subject)
        //        .audience(Collections.singletonList(registeredClient.getClientId()))
        .issuedAt(issuedAt)
        .expiresAt(expiresAt)
        .notBefore(issuedAt)
        .claim("accounts", accounts);
    claimsBuilder.claim(OAuth2ParameterNames.SCOPE, "ACCOUNT_CHOOSER");

    return claimsBuilder;
  }
}
