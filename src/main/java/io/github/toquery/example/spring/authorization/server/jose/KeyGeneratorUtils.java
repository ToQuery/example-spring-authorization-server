package io.github.toquery.example.spring.authorization.server.jose;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * @author Joe Grandja
 * @since 0.1.0
 */
final class KeyGeneratorUtils {

	private KeyGeneratorUtils() {
	}

	static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

}
