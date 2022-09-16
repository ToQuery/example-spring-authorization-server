package io.github.toquery.example.spring.authorization.server.config;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.github.toquery.example.spring.authorization.server.properties.OAuthAuthorizationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Duration;
import java.util.UUID;

/**
 * @author deng.shichao
 */
@Configuration
public class OAuthAuthorizationConfig {

    private final OAuthAuthorizationProperties authAuthorizationProperties;


    public OAuthAuthorizationConfig(OAuthAuthorizationProperties authAuthorizationProperties) {
        this.authAuthorizationProperties = authAuthorizationProperties;
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("example-client-1")
                .clientSecret("{noop}example-client-secret-1")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope("read")
                .scope("write")
                .clientSettings(
                        ClientSettings.builder()
                                //.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
                                .requireAuthorizationConsent(true)
                                .build()
                )
                .tokenSettings(
                        TokenSettings.builder()
                                //使用透明方式，
                                // 默认是 OAuth2TokenFormat SELF_CONTAINED  全的jwt token
                                // REFERENCE 是引用方式，即使用jwt token，但是jwt token是通过oauth2 server生成的，而不是通过oauth2 client生成的
                                //.accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                                // 授权码的有效期
                                .accessTokenTimeToLive(Duration.ofHours(1))
                                // 刷新token的有效期
                                .refreshTokenTimeToLive(Duration.ofDays(3))
                                .reuseRefreshTokens(true)
                                .build()
                )
                .build();


        return new InMemoryRegisteredClientRepository(registeredClient);
    }

//    @Bean
//    public OAuth2AuthorizationService authorizationService(RegisteredClientRepository registeredClientRepository) {
//        return new InMemoryOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
//    }

//    @Bean
//    public OAuth2AuthorizationConsentService authorizationConsentService() {
//        return new InMemoryOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
//    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        JWK jwk = new RSAKey.Builder(authAuthorizationProperties.getPublicKey())
                .privateKey(authAuthorizationProperties.getPrivateKey())
                .algorithm(Algorithm.parse("RS256"))
                .keyID(authAuthorizationProperties.getKeyId())
                .build();
        JWKSet jwkSet = new JWKSet(jwk);
        return (jwkSelector, securityContext) -> {
            return jwkSelector.select(jwkSet);
        };
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().issuer(authAuthorizationProperties.getIssuer()).build();
    }


//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }

    @Bean
    UserDetailsService users() {
        String pwdEncode = new BCryptPasswordEncoder().encode("123456");

        UserDetails user = User.withUsername("admin")
                .password("{bcrypt}" + pwdEncode)
                .roles("ADMIN", "USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

}
