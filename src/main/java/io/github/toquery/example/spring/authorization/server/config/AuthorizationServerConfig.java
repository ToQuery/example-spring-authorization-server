package io.github.toquery.example.spring.authorization.server.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.github.toquery.example.spring.authorization.server.properties.OAuthAuthorizationProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Duration;
import java.util.UUID;

/**
 * @author ToQuery
 */
@RequiredArgsConstructor
@Configuration
public class AuthorizationServerConfig {

    private final OAuthAuthorizationProperties authAuthorizationProperties;


    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        // 获取用户信息
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        http.formLogin(httpSecurityFormLoginConfigurer -> {
        });
        return http.build();
    }

    private RegisteredClient getRegisteredClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(UUID.randomUUID().toString())
                .clientSecret(UUID.randomUUID().toString())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.IMPLICIT)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope(OidcScopes.ADDRESS)
                .scope(OidcScopes.PHONE)
                .scope("read")
                .scope("write")
                .clientSettings(
                        ClientSettings.builder()
                                //.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
                                .requireAuthorizationConsent(false)
                                .build()
                )
                .tokenSettings(
                        TokenSettings.builder()
                                //使用透明方式，
                                // 默认是 OAuth2TokenFormat SELF_CONTAINED  全的jwt token
                                // REFERENCE 是引用方式，即使用jwt token，但是jwt token是通过oauth2 server生成的，而不是通过oauth2 client生成的
                                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                                // 授权码的有效期
                                .accessTokenTimeToLive(Duration.ofHours(1))
                                // 刷新token的有效期
                                .refreshTokenTimeToLive(Duration.ofDays(3))
                                .reuseRefreshTokens(true)
                                .build()
                )
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient jwtClient = RegisteredClient.from(getRegisteredClient())
                .id(UUID.randomUUID().toString())
                .clientId("example-spring-security-jwt")
                .clientName("example-spring-security-jwt")
                .clientSecret("{noop}example-spring-security-jwt-secret")
                .build();

        RegisteredClient jweClient = RegisteredClient.from(getRegisteredClient())
                .id(UUID.randomUUID().toString())
                .clientId("example-spring-security-opaque")
                .clientName("example-spring-security-opaque")
                .clientSecret("{noop}example-spring-security-opaque-secret")
                .tokenSettings(
                        TokenSettings.builder()
                                //使用透明方式，
                                // 默认是 OAuth2TokenFormat SELF_CONTAINED  全的jwt token
                                // REFERENCE 是引用方式，即使用jwt token，但是jwt token是通过oauth2 server生成的，而不是通过oauth2 client生成的
                                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                                // 授权码的有效期
                                .accessTokenTimeToLive(Duration.ofHours(1))
                                // 刷新token的有效期
                                .refreshTokenTimeToLive(Duration.ofDays(3))
                                .reuseRefreshTokens(true)
                                .build()
                )
                .build();


        RegisteredClient ssoJwtClient = RegisteredClient.from(getRegisteredClient())
                .id(UUID.randomUUID().toString())
                .clientId("example-spring-security-oauth2-sso-jwt")
                .clientName("example-spring-security-oauth2-sso-jwt")
                .clientSecret("{noop}example-spring-security-oauth2-sso-jwt-secret")
                .redirectUri("http://spring-security-oauth2-sso-jwt.toquery-example.com:8010/login/oauth2/code/toquery")
                .build();

        RegisteredClient ssoJwt2Client = RegisteredClient.from(getRegisteredClient())
                .id(UUID.randomUUID().toString())
                .clientId("example-spring-security-oauth2-sso-jwt-2")
                .clientName("example-spring-security-oauth2-sso-jwt-2")
                .clientSecret("{noop}example-spring-security-oauth2-sso-jwt-2-secret")
                .redirectUri("http://spring-security-oauth2-sso-jwt.toquery-example.com:8010/login/oauth2/code/toquery")
                .build();

        RegisteredClient ssoOpaqueTokenClient = RegisteredClient.from(getRegisteredClient())
                .id(UUID.randomUUID().toString())
                .clientId("example-spring-security-oauth2-sso-opaque-token")
                .clientName("example-spring-security-oauth2-sso-opaque-token")
                .clientSecret("{noop}example-spring-security-oauth2-sso-opaque-token-secret")
                .redirectUri("http://spring-security-oauth2-sso-opaque-token.toquery-example.com:8020/login/oauth2/code/toquery")
                .build();

        return new InMemoryRegisteredClientRepository(jwtClient, jweClient, ssoJwtClient, ssoJwt2Client, ssoOpaqueTokenClient);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }

    /**
     * 配置jwt解码bean，用于处理获取用户信息（/userinfo）时，解析jwt信息
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * 配置 jwt RSA公钥私钥，最终暴露到 jwkSetEndpoint("/oauth2/jwks") 节点
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        JWK jwk = new RSAKey.Builder(authAuthorizationProperties.getPublicKey())
                .privateKey(authAuthorizationProperties.getPrivateKey())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(authAuthorizationProperties.getKeyId())
                .build();
        JWKSet jwkSet = new JWKSet(jwk);
        return (jwkSelector, securityContext) -> {
            return jwkSelector.select(jwkSet);
        };
    }

    /**
     * 设置暴露的 Endpoint 地址信息
     */
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                .issuer(authAuthorizationProperties.getIssuer())
//                .authorizationEndpoint("/oauth2/authorize")
//                .tokenEndpoint("/oauth2/token")
//                .jwkSetEndpoint("/oauth2/jwks")
//                .tokenRevocationEndpoint("/oauth2/revoke")
//                .tokenIntrospectionEndpoint("/oauth2/introspect")
//                .oidcClientRegistrationEndpoint("/connect/register")
//                .oidcUserInfoEndpoint("/userinfo")
                .build();
    }


}
