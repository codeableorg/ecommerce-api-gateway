package com.ecommerce.api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(exchanges -> exchanges
                        // Public endpoints
                        .pathMatchers("/api/v1/users/register").permitAll()
                        .pathMatchers("/actuator/**").permitAll()
                        // All other endpoints require authentication
                        .anyExchange().authenticated())
                .oauth2Login(oauth2 -> oauth2.loginPage("/oauth2/authorization/keycloak"))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt())
                .csrf().disable()
                .build();
    }
}