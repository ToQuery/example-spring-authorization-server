package io.github.toquery.example.spring.authorization.server;

import io.github.toquery.example.spring.authorization.server.properties.OAuthAuthorizationProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(value = {OAuthAuthorizationProperties.class})
public class ExampleSpringAuthorizationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(ExampleSpringAuthorizationServerApplication.class, args);
    }

}
