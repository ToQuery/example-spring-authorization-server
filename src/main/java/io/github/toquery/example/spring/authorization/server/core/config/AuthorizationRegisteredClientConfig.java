package io.github.toquery.example.spring.authorization.server.core.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

/**
 *
 */
@RequiredArgsConstructor
@Configuration
public class AuthorizationRegisteredClientConfig {

    public static final RegisteredClient defaultRegisteredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(UUID.randomUUID().toString())
            .clientSecret(UUID.randomUUID().toString())
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .authorizationGrantType(AuthorizationGrantType.PASSWORD)
            .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
            .redirectUri("http://127.0.0.1:8080/authorized")
            .redirectUri("http://127.0.0.1:8080/admin/index")
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
                            // .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                            // 授权码的有效期
                            .accessTokenTimeToLive(Duration.ofHours(6))
                            // 刷新token的有效期
                            .refreshTokenTimeToLive(Duration.ofDays(3))
                            .reuseRefreshTokens(true)
                            .build()
            )
            .build();

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient example = RegisteredClient.from(defaultRegisteredClient)
                .id(UUID.randomUUID().toString())
                .clientId("example")
                .clientName("example")
                .clientSecret("{noop}example-secret")
                .build();

        RegisteredClient jwtClient = RegisteredClient.from(defaultRegisteredClient)
                .id(UUID.randomUUID().toString())
                .clientId("example-spring-security-jwt")
                .clientName("example-spring-security-jwt")
                .clientSecret("{noop}example-spring-security-jwt-secret")
                .build();

        RegisteredClient jweClient = RegisteredClient.from(defaultRegisteredClient)
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


        RegisteredClient ssoJwtClient = RegisteredClient.from(defaultRegisteredClient)
                .id(UUID.randomUUID().toString())
                .clientId("example-spring-security-oauth2-sso-jwt")
                .clientName("example-spring-security-oauth2-sso-jwt")
                .clientSecret("{noop}example-spring-security-oauth2-sso-jwt-secret")
                .redirectUri("http://spring-security-oauth2-sso-jwt.toquery-example.com:8010/oauth2/code/toquery")
                .build();

        RegisteredClient ssoJwt2Client = RegisteredClient.from(defaultRegisteredClient)
                .id(UUID.randomUUID().toString())
                .clientId("example-spring-security-oauth2-sso-jwt-2")
                .clientName("example-spring-security-oauth2-sso-jwt-2")
                .clientSecret("{noop}example-spring-security-oauth2-sso-jwt-2-secret")
                .redirectUri("http://spring-security-oauth2-sso-jwt.toquery-example.com:8010/login/oauth2/code/toquery")
                .build();

        RegisteredClient ssoOpaqueTokenClient = RegisteredClient.from(defaultRegisteredClient)
                .id(UUID.randomUUID().toString())
                .clientId("example-spring-security-oauth2-sso-opaque-token")
                .clientName("example-spring-security-oauth2-sso-opaque-token")
                .clientSecret("{noop}example-spring-security-oauth2-sso-opaque-token-secret")
                .redirectUri("http://spring-security-oauth2-sso-opaque-token.toquery-example.com:8020/login/oauth2/code/toquery")
                .build();

        return new InMemoryRegisteredClientRepository(example, jwtClient, jweClient, ssoJwtClient, ssoJwt2Client, ssoOpaqueTokenClient);

    }
}
