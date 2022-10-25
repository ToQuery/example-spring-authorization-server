package io.github.toquery.example.spring.authorization.server.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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


    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.formLogin(httpSecurityFormLoginConfigurer -> {
        });
        http.authorizeRequests(authorizeRequests -> {
            authorizeRequests.anyRequest().authenticated();
        });
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
