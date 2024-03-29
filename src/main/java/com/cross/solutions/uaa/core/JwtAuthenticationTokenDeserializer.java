package com.cross.solutions.uaa.core;

import java.io.IOException;
import java.util.List;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * Custom deserializer for {@link UsernamePasswordAuthenticationToken}. At the time of
 * deserialization it will invoke suitable constructor depending on the value of
 * <b>authenticated</b> property. It will ensure that the token's state must not change.
 *
 * <p>This deserializer is already registered with {@link UsernamePasswordAuthenticationTokenMixin}
 * but you can also registered it with your own mixin class.
 *
 * @author Jitendra Singh
 * @author Greg Turnquist
 * @author Onur Kagan Ozcan
 * @since 4.2
 * @see UsernamePasswordAuthenticationTokenMixin
 */
class JwtAuthenticationTokenDeserializer extends JsonDeserializer<JwtAuthenticationToken> {

  private static final TypeReference<List<GrantedAuthority>> GRANTED_AUTHORITY_LIST =
      new TypeReference<List<GrantedAuthority>>() {};

  private static final TypeReference<Object> OBJECT = new TypeReference<Object>() {};

  /**
   * This method construct {@link UsernamePasswordAuthenticationToken} object from serialized json.
   *
   * @param jp the JsonParser
   * @param ctxt the DeserializationContext
   * @return the user
   * @throws IOException if a exception during IO occurs
   * @throws JsonProcessingException if an error during JSON processing occurs
   */
  @Override
  public JwtAuthenticationToken deserialize(JsonParser jp, DeserializationContext ctxt)
      throws IOException, JsonProcessingException {
    ObjectMapper mapper = (ObjectMapper) jp.getCodec();
    JsonNode jsonNode = mapper.readTree(jp);
    Boolean authenticated = readJsonNode(jsonNode, "authenticated").asBoolean();
    JsonNode principalNode = readJsonNode(jsonNode, "principal");
    AuthenticationUser principal = getPrincipal(mapper, principalNode);
    JsonNode credentialsNode = readJsonNode(jsonNode, "credentials");
    RawJwtToken credentials = getCredentials(mapper, credentialsNode);
    List<GrantedAuthority> authorities =
        mapper.readValue(
            readJsonNode(jsonNode, "authorities").traverse(mapper), GRANTED_AUTHORITY_LIST);
    JwtAuthenticationToken token =
        (!authenticated)
            ? new JwtAuthenticationToken(credentials)
            : new JwtAuthenticationToken(principal, authorities);
    JsonNode detailsNode = readJsonNode(jsonNode, "details");
    if (detailsNode.isNull() || detailsNode.isMissingNode()) {
      token.setDetails(null);
    } else {
      Object details = mapper.readValue(detailsNode.toString(), OBJECT);
      token.setDetails(details);
    }
    return token;
  }

  private RawJwtToken getCredentials(ObjectMapper mapper, JsonNode credentialsNode)
      throws JsonParseException, JsonMappingException, IOException {
    if (credentialsNode.isNull() || credentialsNode.isMissingNode()) {
      return null;
    }
    if (credentialsNode.isObject()) {
      return mapper.readValue(credentialsNode.traverse(mapper), RawJwtToken.class);
    }
    return null;
  }

  private AuthenticationUser getPrincipal(ObjectMapper mapper, JsonNode principalNode)
      throws IOException, JsonParseException, JsonMappingException {
    if (principalNode.isObject()) {
      return mapper.readValue(principalNode.traverse(mapper), AuthenticationUser.class);
    }
    return null;
  }

  private JsonNode readJsonNode(JsonNode jsonNode, String field) {
    return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
  }
}
