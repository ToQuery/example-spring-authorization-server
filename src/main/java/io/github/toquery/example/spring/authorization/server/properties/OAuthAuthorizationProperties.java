package io.github.toquery.example.spring.authorization.server.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author ToQuery
 */
@Data
@ConfigurationProperties(
        prefix = "app.oauth"
)
public class OAuthAuthorizationProperties {

    private String issuer = "http://localhost:8080";

    private String keyId = "123456";

    private RSAPublicKey publicKey;

    private RSAPrivateKey privateKey;
}
