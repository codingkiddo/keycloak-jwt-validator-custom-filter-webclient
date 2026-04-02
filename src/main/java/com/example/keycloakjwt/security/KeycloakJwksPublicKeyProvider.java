package com.example.keycloakjwt.security;

import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class KeycloakJwksPublicKeyProvider {

    private static final Logger log = LoggerFactory.getLogger(KeycloakJwksPublicKeyProvider.class);

    private final WebClient webClient;
    private final KeycloakJwtProperties properties;
    private final Map<String, IssuerCacheEntry> cacheByIssuer = new ConcurrentHashMap<>();

    public KeycloakJwksPublicKeyProvider(WebClient jwksWebClient,
                                         KeycloakJwtProperties properties) {
        this.webClient = jwksWebClient;
        this.properties = properties;
    }

    public RSAPublicKey getPublicKey(String issuer, String kid) {
        String normalizedIssuer = KeycloakJwtProperties.normalizeIssuer(issuer);
        IssuerCacheEntry entry = cacheByIssuer.computeIfAbsent(normalizedIssuer, key -> new IssuerCacheEntry());

        RSAPublicKey cached = entry.keysByKid.get(kid);
        if (cached != null && entry.isFresh()) {
            return cached;
        }

        synchronized (entry.monitor) {
            cached = entry.keysByKid.get(kid);
            if (cached != null && entry.isFresh()) {
                return cached;
            }

            refreshIssuerKeys(normalizedIssuer, entry);

            RSAPublicKey refreshed = entry.keysByKid.get(kid);
            if (refreshed == null) {
                throw new BadJwtException("No public key found for issuer=" + normalizedIssuer + ", kid=" + kid);
            }
            return refreshed;
        }
    }

    void refreshIssuerKeys(String issuer, IssuerCacheEntry entry) {
        String jwksUrl = KeycloakJwtProperties.jwksUrlForIssuer(issuer);

        final JsonNode jwks;
        try {
            jwks = webClient.get()
                    .uri(jwksUrl)
                    .retrieve()
                    .bodyToMono(JsonNode.class)
                    .block();
        } catch (WebClientResponseException ex) {
            throw new BadJwtException(
                    "Failed to fetch JWKS from " + jwksUrl + ": HTTP " + ex.getStatusCode().value() +
                            " - " + ex.getResponseBodyAsString(),
                    ex
            );
        } catch (Exception ex) {
            Throwable root = NestedExceptionUtils.getMostSpecificCause(ex);
            log.error("Failed to fetch JWKS from {}", jwksUrl, ex);
            throw new BadJwtException(
                    "Failed to fetch JWKS from " + jwksUrl + ": " +
                            root.getClass().getSimpleName() + " - " + root.getMessage(),
                    ex
            );
        }

        if (jwks == null || !jwks.has("keys") || !jwks.get("keys").isArray()) {
            throw new BadJwtException("Invalid JWKS payload from " + jwksUrl);
        }

        Map<String, RSAPublicKey> parsedKeys = new HashMap<>();
        for (JsonNode jwk : jwks.get("keys")) {
            String kid = text(jwk, "kid");
            if (!StringUtils.hasText(kid)) {
                continue;
            }

            RSAPublicKey publicKey = extractRsaPublicKey(jwk);
            if (publicKey != null) {
                parsedKeys.put(kid, publicKey);
            }
        }

        if (parsedKeys.isEmpty()) {
            throw new BadJwtException("No usable RSA public keys found at " + jwksUrl);
        }

        entry.keysByKid = Collections.unmodifiableMap(parsedKeys);
        entry.expiresAt = Instant.now().plus(properties.getJwksCacheTtl());
    }

    private RSAPublicKey extractRsaPublicKey(JsonNode jwk) {
        try {
            JsonNode x5c = jwk.get("x5c");
            if (x5c != null && x5c.isArray() && !x5c.isEmpty()) {
                return fromX5c(x5c.get(0).asText());
            }

            String modulus = text(jwk, "n");
            String exponent = text(jwk, "e");
            if (StringUtils.hasText(modulus) && StringUtils.hasText(exponent)) {
                return fromModulusAndExponent(modulus, exponent);
            }

            return null;
        } catch (Exception ex) {
            return null;
        }
    }

    private RSAPublicKey fromX5c(String x5cValue) throws Exception {
        byte[] der = Base64.getDecoder().decode(x5cValue);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(der));
        PublicKey publicKey = certificate.getPublicKey();
        if (!(publicKey instanceof RSAPublicKey rsaPublicKey)) {
            throw new IllegalArgumentException("Certificate public key is not RSA");
        }
        return rsaPublicKey;
    }

    private RSAPublicKey fromModulusAndExponent(String n, String e) throws Exception {
        byte[] modulusBytes = Base64.getUrlDecoder().decode(n);
        byte[] exponentBytes = Base64.getUrlDecoder().decode(e);

        BigInteger modulus = new BigInteger(1, modulusBytes);
        BigInteger exponent = new BigInteger(1, exponentBytes);

        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    private String text(JsonNode node, String fieldName) {
        JsonNode value = node.get(fieldName);
        return value == null || value.isNull() ? null : value.asText();
    }

    static final class IssuerCacheEntry {
        private final Object monitor = new Object();
        private volatile Map<String, RSAPublicKey> keysByKid = Map.of();
        private volatile Instant expiresAt = Instant.EPOCH;

        boolean isFresh() {
            return Instant.now().isBefore(expiresAt);
        }
    }
}
