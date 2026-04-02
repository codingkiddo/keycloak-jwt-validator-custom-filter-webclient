package com.example.keycloakjwt.security.config;

import com.example.keycloakjwt.security.KeycloakJwksPublicKeyProvider;
import com.example.keycloakjwt.security.filter.JwtTokenAuthenticationFilter;
import com.example.keycloakjwt.security.support.ClientConfigurations;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private final ClientConfigurations clientConfigurations;
    private final KeycloakJwksPublicKeyProvider keycloakJwksPublicKeyProvider;

    public WebSecurityConfig(ClientConfigurations clientConfigurations,
                             KeycloakJwksPublicKeyProvider keycloakJwksPublicKeyProvider) {
        this.clientConfigurations = clientConfigurations;
        this.keycloakJwksPublicKeyProvider = keycloakJwksPublicKeyProvider;
    }

    @Bean
    protected SecurityFilterChain filterChain(
            HttpSecurity http,
            @Value("#{'${config.secapi.auth.allowed-issuers}'.split(',')}") List<String> allowedIssuers
    ) throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex.authenticationEntryPoint(
                        (req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage())
                ))
                .addFilterAfter(
                        new JwtTokenAuthenticationFilter(
                                clientConfigurations,
                                keycloakJwksPublicKeyProvider,
                                allowedIssuers
                        ),
                        UsernamePasswordAuthenticationFilter.class
                )
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/public/**", "/actuator/health").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> {
            web.ignoring().requestMatchers(HttpMethod.OPTIONS, "/**");
            web.ignoring().requestMatchers(
                    "/v2/api-docs",
                    "/swagger-resources/**",
                    "/swagger-ui/**",
                    "/swagger-ui.html",
                    "/webjars/**"
            );
        };
    }
}
