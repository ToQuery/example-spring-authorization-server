package io.github.toquery.example.spring.authorization.server.core.properties;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.converter.RsaKeyConverters;

import java.io.File;
import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author ToQuery
 */
@Slf4j
@Data
@ConfigurationProperties(
        prefix = "app.oauth"
)
public class OAuthAuthorizationProperties {

    private String keyId = "123456";

    private RSAPublicKey publicKey;

    private RSAPrivateKey privateKey;

    {
        try {
            publicKey = RsaKeyConverters.x509().convert(new DefaultResourceLoader().getResource(ResourceLoader.CLASSPATH_URL_PREFIX + "jwts" + File.separator + "rsa_public.isa").getInputStream());
        } catch (IOException e) {
            log.error("加载JWT公钥失败", e);
            throw new RuntimeException(e);
        }
        try {
            privateKey = RsaKeyConverters.pkcs8().convert(new DefaultResourceLoader().getResource(ResourceLoader.CLASSPATH_URL_PREFIX + "jwts" + File.separator + "rsa_private.isa").getInputStream());
        } catch (IOException e) {
            log.error("加载JWT私钥失败", e);
            throw new RuntimeException(e);
        }
    }
}
