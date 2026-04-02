package com.example.keycloakjwt.api;

import com.example.keycloakjwt.security.KeycloakJwksPublicKeyProvider;
import com.example.keycloakjwt.security.filter.JwtTokenAuthenticationFilter;
import com.example.keycloakjwt.security.support.ClientConfigurations;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

@TestConfiguration
class TestSecurityConfig {

    @Bean
    SecurityFilterChain testSecurityFilterChain(HttpSecurity http,
                                                ClientConfigurations clientConfigurations,
                                                KeycloakJwksPublicKeyProvider keycloakJwksPublicKeyProvider) throws Exception {

        List<String> allowedIssuers = List.of("https://auth-dev.local/realms/platform");

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/public/**").permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, authException) ->
                                response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                )
                .addFilterAfter(
                        new JwtTokenAuthenticationFilter(
                                clientConfigurations,
                                keycloakJwksPublicKeyProvider,
                                allowedIssuers
                        ),
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }
}
