package com.example.keycloakjwt.security;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.web.reactive.function.client.WebClient;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeycloakJwksPublicKeyProviderTest {

    private MockWebServer server;
    private KeycloakJwksPublicKeyProvider provider;

    @BeforeEach
    void setUp() throws Exception {
        server = new MockWebServer();
        server.start();

        KeycloakJwtProperties properties = new KeycloakJwtProperties();
        properties.setJwksCacheTtl(Duration.ofMinutes(30));
        properties.setReadTimeout(Duration.ofSeconds(5));

        WebClient webClient = WebClient.builder().build();
        provider = new KeycloakJwksPublicKeyProvider(webClient, properties);
    }

    @AfterEach
    void tearDown() throws Exception {
        server.shutdown();
    }

    @Test
    void loadsPublicKeyFromModulusAndExponentAndCachesByKid() {
        KeyPair pair = JwtTestUtils.generateRsaKeyPair();
        RSAPublicKey expected = (RSAPublicKey) pair.getPublic();

        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody(JwtTestUtils.rsaJwksJson("kid-1", expected)));

        String issuer = server.url("/realms/platform").toString();

        RSAPublicKey actual1 = provider.getPublicKey(issuer, "kid-1");
        RSAPublicKey actual2 = provider.getPublicKey(issuer, "kid-1");

        assertThat(actual1.getModulus()).isEqualTo(expected.getModulus());
        assertThat(actual1.getPublicExponent()).isEqualTo(expected.getPublicExponent());
        assertThat(actual2.getModulus()).isEqualTo(expected.getModulus());
        assertThat(server.getRequestCount()).isEqualTo(1);
    }

    @Test
    void refreshesCacheWhenKidIsMissing() {
        KeyPair oldPair = JwtTestUtils.generateRsaKeyPair();
        KeyPair newPair = JwtTestUtils.generateRsaKeyPair();

        RSAPublicKey oldKey = (RSAPublicKey) oldPair.getPublic();
        RSAPublicKey newKey = (RSAPublicKey) newPair.getPublic();

        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody(JwtTestUtils.rsaJwksJson("kid-old", oldKey)));

        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody(JwtTestUtils.rsaJwksJson("kid-old", oldKey, "kid-new", newKey)));

        String issuer = server.url("/realms/platform").toString();

        RSAPublicKey first = provider.getPublicKey(issuer, "kid-old");
        RSAPublicKey second = provider.getPublicKey(issuer, "kid-new");

        assertThat(first.getModulus()).isEqualTo(oldKey.getModulus());
        assertThat(second.getModulus()).isEqualTo(newKey.getModulus());
        assertThat(server.getRequestCount()).isEqualTo(2);
    }

    @Test
    void keepsSameKidSeparatedByIssuer() {
        KeyPair firstPair = JwtTestUtils.generateRsaKeyPair();
        KeyPair secondPair = JwtTestUtils.generateRsaKeyPair();

        RSAPublicKey firstKey = (RSAPublicKey) firstPair.getPublic();
        RSAPublicKey secondKey = (RSAPublicKey) secondPair.getPublic();

        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody(JwtTestUtils.rsaJwksJson("shared-kid", firstKey)));

        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody(JwtTestUtils.rsaJwksJson("shared-kid", secondKey)));

        String issuerA = server.url("/realms/platform-a").toString();
        String issuerB = server.url("/realms/platform-b").toString();

        RSAPublicKey resolvedA = provider.getPublicKey(issuerA, "shared-kid");
        RSAPublicKey resolvedB = provider.getPublicKey(issuerB, "shared-kid");

        assertThat(resolvedA.getModulus()).isEqualTo(firstKey.getModulus());
        assertThat(resolvedB.getModulus()).isEqualTo(secondKey.getModulus());
        assertThat(server.getRequestCount()).isEqualTo(2);
    }

    @Test
    void throwsHelpfulMessageWhenJwksEndpointReturnsHttpError() {
        server.enqueue(new MockResponse().setResponseCode(404).setBody("not found"));

        String issuer = server.url("/realms/platform").toString();

        assertThatThrownBy(() -> provider.getPublicKey(issuer, "kid-1"))
                .isInstanceOf(BadJwtException.class)
                .hasMessageContaining("HTTP 404")
                .hasMessageContaining("not found");
    }

    @Test
    void throwsWhenJwksPayloadIsInvalid() {
        server.enqueue(new MockResponse()
                .setHeader("Content-Type", "application/json")
                .setBody("{\"invalid\":true}"));

        String issuer = server.url("/realms/platform").toString();

        assertThatThrownBy(() -> provider.getPublicKey(issuer, "kid-1"))
                .isInstanceOf(BadJwtException.class)
                .hasMessageContaining("Invalid JWKS payload");
    }
}
