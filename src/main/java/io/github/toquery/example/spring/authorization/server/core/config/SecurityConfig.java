package io.github.toquery.example.spring.authorization.server.core.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.time.Duration;

/**
 *
 */
@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

    @Bean
    public CorsConfiguration corsConfiguration() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.addAllowedOriginPattern("*");
        corsConfiguration.addAllowedHeader("*");
        corsConfiguration.addAllowedMethod("*");
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setMaxAge(Duration.ofDays(7));
        return corsConfiguration;
    }


    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(
            HttpSecurity http,
            CorsConfiguration corsConfiguration
            ) throws Exception {

//        FederatedIdentityConfigurer federatedIdentityConfigurer = new FederatedIdentityConfigurer().oauth2UserHandler(new UserRepositoryOAuth2UserHandler());

        http.cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(exchange -> corsConfiguration));
        http.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
            // 白名单
            authorizationManagerRequestMatcherRegistry.requestMatchers("/", "/error").permitAll();
            authorizationManagerRequestMatcherRegistry.requestMatchers("/actuator", "/actuator/*").permitAll();

            authorizationManagerRequestMatcherRegistry.anyRequest().authenticated();
        });


        // Form login handles the redirect to the login page from the
        // authorization server filter chain
        http.formLogin(Customizer.withDefaults());
//        http.formLogin(httpSecurityFormLoginConfigurer -> {
//            httpSecurityFormLoginConfigurer.loginPage("/login").failureUrl("/login-error").permitAll();
//        });

//        http .csrf(httpSecurityCsrfConfigurer -> {
//            httpSecurityCsrfConfigurer.ignoringRequestMatchers(PathRequest.toH2Console());
//        });
//        http.headers(httpSecurityHeadersConfigurer -> {
//            httpSecurityHeadersConfigurer.frameOptions(frameOptionsConfig -> {
//                frameOptionsConfig.sameOrigin();
//            });
//        });

//        http.apply(federatedIdentityConfigurer);

        return http.build();
    }


    @Bean
    public UserDetailsService userDetailsService() {
        String pwdEncode = new BCryptPasswordEncoder().encode("123456");

        UserDetails user = User.withUsername("admin")
                .password("{bcrypt}" + pwdEncode)
                .roles("ADMIN", "USER")
                .authorities("ADMIN", "USER")
                .disabled(false)
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
