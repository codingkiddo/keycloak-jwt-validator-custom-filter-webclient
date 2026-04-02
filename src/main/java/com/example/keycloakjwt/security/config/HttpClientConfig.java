package com.example.keycloakjwt.security.config;

import com.example.keycloakjwt.security.KeycloakJwtProperties;
import io.netty.channel.ChannelOption;
import org.springframework.boot.autoconfigure.web.reactive.function.client.WebClientSsl;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

@Configuration
@EnableConfigurationProperties(KeycloakJwtProperties.class)
public class HttpClientConfig {

    @Bean
    WebClient jwksWebClient(WebClient.Builder builder,
                            WebClientSsl ssl,
                            KeycloakJwtProperties properties) {

        HttpClient httpClient = HttpClient.create()
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS,
                        Math.toIntExact(properties.getConnectTimeout().toMillis()))
                .responseTimeout(properties.getReadTimeout());

        return builder
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .apply(ssl.fromBundle("keycloak-jwks"))
                .build();
    }
}
