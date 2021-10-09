package com.cross.solutions.uaa.core;

import java.io.IOException;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;

/**
 * Custom Deserializer for {@link AuthenticationUser} class. This is already registered with {@link
 * AuthenticationUserMixin}. You can also use it directly with your mixin class.
 *
 * @author
 * @since
 * @see AuthenticationUserMixin
 */
class AuthenticationUserDeserializer extends JsonDeserializer<AuthenticationUser> {

  private static final TypeReference<Set<SimpleGrantedAuthority>> SIMPLE_GRANTED_AUTHORITY_SET =
      new TypeReference<Set<SimpleGrantedAuthority>>() {};

  /**
   * This method will create {@link AuthenticationUser} object. It will ensure successful object
   * creation even if password key is null in serialized json, because credentials may be removed
   * from the {@link AuthenticationUser} by invoking {@link AuthenticationUser#eraseCredentials()}.
   * In that case there won't be any password key in serialized json.
   *
   * @param jp the JsonParser
   * @param ctxt the DeserializationContext
   * @return the user
   * @throws IOException if a exception during IO occurs
   * @throws JsonProcessingException if an error during JSON processing occurs
   */
  @Override
  public AuthenticationUser deserialize(JsonParser jp, DeserializationContext ctxt)
      throws IOException, JsonProcessingException {
    ObjectMapper mapper = (ObjectMapper) jp.getCodec();
    JsonNode jsonNode = mapper.readTree(jp);
    Set<? extends GrantedAuthority> authorities =
        mapper.convertValue(jsonNode.get("authorities"), SIMPLE_GRANTED_AUTHORITY_SET);
    JsonNode passwordNode = readJsonNode(jsonNode, "password");
    String username = readJsonNode(jsonNode, "username").asText();
    String password = passwordNode.asText("");
    String firstname = readJsonNode(jsonNode, "firstname").asText();
    String lastname = readJsonNode(jsonNode, "lastname").asText();
    boolean enabled = readJsonNode(jsonNode, "enabled").asBoolean();
    boolean accountNonExpired = readJsonNode(jsonNode, "accountNonExpired").asBoolean();
    boolean credentialsNonExpired = readJsonNode(jsonNode, "credentialsNonExpired").asBoolean();
    boolean accountNonLocked = readJsonNode(jsonNode, "accountNonLocked").asBoolean();
    AuthenticationUser result =
        new AuthenticationUser(
            username,
            password,
            firstname,
            lastname,
            enabled,
            accountNonExpired,
            credentialsNonExpired,
            accountNonLocked,
            authorities);
    if (passwordNode.asText(null) == null) {
      result.eraseCredentials();
    }
    return result;
  }

  private JsonNode readJsonNode(JsonNode jsonNode, String field) {
    return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
  }
}
