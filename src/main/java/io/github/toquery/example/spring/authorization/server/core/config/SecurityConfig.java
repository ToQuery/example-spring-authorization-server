package io.github.toquery.example.spring.authorization.server.core.config;

import io.github.toquery.example.spring.authorization.server.core.oauth2.federated.identity.FederatedIdentityConfigurer;
import io.github.toquery.example.spring.authorization.server.core.oauth2.federated.identity.UserRepositoryOAuth2UserHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 *
 */
@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//        return (web) -> web.ignoring().requestMatchers("/webjars/**", "/image/**");
//    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

//        FederatedIdentityConfigurer federatedIdentityConfigurer = new FederatedIdentityConfigurer().oauth2UserHandler(new UserRepositoryOAuth2UserHandler());


        http.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
            authorizationManagerRequestMatcherRegistry.requestMatchers("/error", "/", "/actuator**").permitAll();
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
