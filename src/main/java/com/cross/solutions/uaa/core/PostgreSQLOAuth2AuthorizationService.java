package com.cross.solutions.uaa.core;

import java.nio.charset.StandardCharsets;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;

import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * A PostgresSQL version of {@link JdbcOAuth2AuthorizationService}.
 *
 * @author huynhlehoaibac
 * @since 0.0.1-SNAPSHOT
 * @see JdbcOAuth2AuthorizationService
 */
public class PostgreSQLOAuth2AuthorizationService extends JdbcOAuth2AuthorizationService {

  private static final String COLUMN_NAMES =
      "id, "
          + "registered_client_id, "
          + "principal_name, "
          + "authorization_grant_type, "
          + "attributes, "
          + "state, "
          + "authorization_code_value, "
          + "authorization_code_issued_at, "
          + "authorization_code_expires_at,"
          + "authorization_code_metadata,"
          + "access_token_value,"
          + "access_token_issued_at,"
          + "access_token_expires_at,"
          + "access_token_metadata,"
          + "access_token_type,"
          + "access_token_scopes,"
          + "oidc_id_token_value,"
          + "oidc_id_token_issued_at,"
          + "oidc_id_token_expires_at,"
          + "oidc_id_token_metadata,"
          + "refresh_token_value,"
          + "refresh_token_issued_at,"
          + "refresh_token_expires_at,"
          + "refresh_token_metadata";

  private static final String TABLE_NAME = "oauth2_authorization";

  private static final String UNKNOWN_TOKEN_TYPE_FILTER =
      "state = ? OR authorization_code_value = ? OR "
          + "access_token_value = ? OR refresh_token_value = ?";

  private static final String STATE_FILTER = "state = ?";
  private static final String AUTHORIZATION_CODE_FILTER = "authorization_code_value = ?";
  private static final String ACCESS_TOKEN_FILTER = "access_token_value = ?";
  private static final String REFRESH_TOKEN_FILTER = "refresh_token_value = ?";

  private static final String LOAD_AUTHORIZATION_SQL =
      "SELECT " + COLUMN_NAMES + " FROM " + TABLE_NAME + " WHERE ";

  public PostgreSQLOAuth2AuthorizationService(
      JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
    super(jdbcOperations, registeredClientRepository);
  }

  @Nullable
  @Override
  public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
    Assert.hasText(token, "token cannot be empty");
    List<SqlParameterValue> parameters = new ArrayList<>();
    if (tokenType == null) {
      parameters.add(new SqlParameterValue(Types.VARCHAR, token));
      parameters.add(new SqlParameterValue(Types.BINARY, token.getBytes(StandardCharsets.UTF_8)));
      parameters.add(new SqlParameterValue(Types.BINARY, token.getBytes(StandardCharsets.UTF_8)));
      parameters.add(new SqlParameterValue(Types.BINARY, token.getBytes(StandardCharsets.UTF_8)));
      return findBy(UNKNOWN_TOKEN_TYPE_FILTER, parameters);
    } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
      parameters.add(new SqlParameterValue(Types.VARCHAR, token));
      return findBy(STATE_FILTER, parameters);
    } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
      parameters.add(new SqlParameterValue(Types.BINARY, token.getBytes(StandardCharsets.UTF_8)));
      return findBy(AUTHORIZATION_CODE_FILTER, parameters);
    } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
      parameters.add(new SqlParameterValue(Types.BINARY, token.getBytes(StandardCharsets.UTF_8)));
      return findBy(ACCESS_TOKEN_FILTER, parameters);
    } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
      parameters.add(new SqlParameterValue(Types.BINARY, token.getBytes(StandardCharsets.UTF_8)));
      return findBy(REFRESH_TOKEN_FILTER, parameters);
    }
    return null;
  }

  private OAuth2Authorization findBy(String filter, List<SqlParameterValue> parameters) {
    PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
    List<OAuth2Authorization> result =
        this.getJdbcOperations()
            .query(LOAD_AUTHORIZATION_SQL + filter, pss, this.getAuthorizationRowMapper());
    return !result.isEmpty() ? result.get(0) : null;
  }
}
