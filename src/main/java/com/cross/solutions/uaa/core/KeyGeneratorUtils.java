package com.cross.solutions.uaa.core;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.core.io.ClassPathResource;
import org.springframework.security.converter.RsaKeyConverters;

import com.nimbusds.jose.jwk.RSAKey;

/**
 * Using cmd to generate private key and public key
 *
 * <pre>
 * # create private key in PEM format
 * openssl genrsa -out private.pem 2048
 *
 * openssl rsa -in private.pem -pubout > public.pem
 *
 * # convert the private key in pkcs1 to pkcs8 so it can read by Java
 * openssl pkcs8 -topk8 -inform PEM -outform PEM -in private.pem -out private_p8.pem -nocrypt
 * </pre>
 *
 * @author huynhlehoaibac
 * @since 0.0.1-SNAPSHOT
 */
public class KeyGeneratorUtils {

  private KeyGeneratorUtils() {}

  /**
   * Load RSAKey from files
   *
   * @return keyPair
   * @throws Exception
   */
  public static RSAKey loadKeyPair() throws Exception {
    RSAPrivateKey privateKey =
        RsaKeyConverters.pkcs8()
            .convert(new ClassPathResource("key/private_p8.pem").getInputStream());
    RSAPublicKey publicKey =
        RsaKeyConverters.x509().convert(new ClassPathResource("key/public.pem").getInputStream());

    return new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        // .keyID(UUID.randomUUID().toString())
        .build();
  }
}
