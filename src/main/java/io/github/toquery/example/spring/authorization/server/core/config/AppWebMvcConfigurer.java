package io.github.toquery.example.spring.authorization.server.core.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 *
 */
@Slf4j
@EnableWebMvc
@Configuration
public class AppWebMvcConfigurer implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        log.info("app - cors 开启");
        //添加映射路径
        registry.addMapping("/**")
                //放行哪些原始域
                .allowedOriginPatterns("*") // SpringBoot2.4.0 [allowedOriginPatterns]代替[allowedOrigins]  .allowedOrigins("*")
                //是否发送Cookie信息
                .allowCredentials(true)
                //放行哪些原始域(请求方式)
                .allowedMethods("GET", "POST", "PUT", "DELETE")
                //放行哪些原始域(头部信息)
                .allowedHeaders("*");
    }
}
