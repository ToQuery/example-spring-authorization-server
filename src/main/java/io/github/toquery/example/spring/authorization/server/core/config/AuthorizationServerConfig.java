package io.github.toquery.example.spring.authorization.server.core.config;

import com.bty.platform.oauth.authorization.utils.RSAUtils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.github.toquery.example.spring.authorization.server.core.oauth2.authentication.OAuth2ResourceOwnerPasswordAuthenticationConverter;
import io.github.toquery.example.spring.authorization.server.core.oauth2.authentication.OAuth2ResourceOwnerPasswordAuthenticationProvider;
import io.github.toquery.example.spring.authorization.server.core.oauth2.federated.identity.FederatedIdentityConfigurer;
import io.github.toquery.example.spring.authorization.server.core.oauth2.federated.identity.UserRepositoryOAuth2UserHandler;
import io.github.toquery.example.spring.authorization.server.core.properties.AppJwtProperties;
import io.github.toquery.example.spring.authorization.server.core.utils.OAuth2ConfigurerUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;
import java.util.List;

/**
 * @author ToQuery
 */
@RequiredArgsConstructor
@Configuration
public class AuthorizationServerConfig {


    private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

    private final AppJwtProperties authAuthorizationProperties;


    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            CorsConfiguration corsConfiguration
            ) throws Exception {
        // 配置默认设置
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        // 获取默认设置项
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = http.getConfigurer(OAuth2AuthorizationServerConfigurer.class);

        // 应用 OAuth2AuthorizationServer 配置
         http.with(authorizationServerConfigurer, (authorizationServer) -> {
             // 自定义 token 接口，支持 password 方式获取token
//             authorizationServer.tokenEndpoint((tokenEndpoint) -> {
//                 List<AuthenticationConverter> converters = Arrays.asList(
//                         new OAuth2AuthorizationCodeAuthenticationConverter(),
//                         new OAuth2RefreshTokenAuthenticationConverter(),
//                         new OAuth2ClientCredentialsAuthenticationConverter(),
//                         new OAuth2ResourceOwnerPasswordAuthenticationConverter());
//                 // 委托模式认证转换器
//                 AuthenticationConverter authenticationConverter = new DelegatingAuthenticationConverter(converters);
//                 tokenEndpoint.accessTokenRequestConverter(authenticationConverter);
//             });

             // Enable OpenID Connect 1.0
             authorizationServer.oidc(Customizer.withDefaults());

         });

        http.cors(httpSecurityCorsConfigurer -> {
            httpSecurityCorsConfigurer.configurationSource(request -> corsConfiguration);
        });

        http.headers(httpSecurityHeadersConfigurer -> {
            httpSecurityHeadersConfigurer.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable);
        });

//        SSO 集成 github Google 账号使用
        FederatedIdentityConfigurer federatedIdentityConfigurer = new FederatedIdentityConfigurer();
        http.with(federatedIdentityConfigurer, (federatedIdentity) -> {
            federatedIdentity.loginPageUrl("/login");
            federatedIdentity.authorizationRequestUri("/oauth2/authorization/{registrationId}");
            federatedIdentity.oauth2UserHandler(new UserRepositoryOAuth2UserHandler());
        });


        // 获取用户信息 Accept access tokens for User Info and/or Client Registration
        http.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));

        // Redirect to the login page when not authenticated from the
        // authorization endpoint
        http.exceptionHandling((exceptionHandlingConfigurer) -> {
            exceptionHandlingConfigurer.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML));
        });


        SecurityFilterChain securityFilterChain = http.formLogin(Customizer.withDefaults()).build();

        /**
         * 必须在 .build() 方法后获取 http.getSharedObject 对象
         * Custom configuration for Resource Owner Password grant type. Current implementation has no support for Resource Owner
         * Password grant type
         */
//        addCustomOAuth2ResourceOwnerPasswordAuthenticationProvider(http);

        return securityFilterChain;
    }

    private void addCustomOAuth2ResourceOwnerPasswordAuthenticationProvider(HttpSecurity httpSecurity) {

        AuthenticationManager authenticationManager = OAuth2ConfigurerUtils.getAuthenticationManager(httpSecurity);
        OAuth2AuthorizationService authorizationService = OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);
        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity);

        OAuth2ResourceOwnerPasswordAuthenticationProvider resourceOwnerPasswordAuthenticationProvider = new OAuth2ResourceOwnerPasswordAuthenticationProvider(authenticationManager, authorizationService, tokenGenerator);

        // This will add new authentication provider in the list of existing authentication providers.
        httpSecurity.authenticationProvider(resourceOwnerPasswordAuthenticationProvider);

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
        JWK jwk = new RSAKey.Builder(RSAUtils.publicKey(authAuthorizationProperties.getPublicKey()))
                .privateKey(RSAUtils.privateKey(authAuthorizationProperties.getPrivateKey()))
                .keyID(authAuthorizationProperties.getKeyId())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
        JWKSet jwkSet = new JWKSet(jwk);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource){
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * <a href="https://github.com/spring-projects/spring-authorization-server/issues/500">...</a>
     */
//    @Bean
//    public OAuth2TokenGenerator<? extends OAuth2Token> JwtGenerator(JwtEncoder jwtEncoder) {
//        return new JwtGenerator(jwtEncoder);
//    }

    /**
     * 设置暴露的 Endpoint 地址信息
     */
    @Bean
    public AuthorizationServerSettings providerSettings() {
        return AuthorizationServerSettings.builder()
                .build();
    }


}
