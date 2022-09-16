package io.github.toquery.example.spring.authorization.server.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author deng.shichao
 */
@Data
@ConfigurationProperties(
        prefix = "app.oauth"
)
public class OAuthAuthorizationProperties {
    private String issuer = "http://localhost:8080/";
}
