package com.example.keycloakjwt.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

public final class JwtTestUtils {

    private JwtTestUtils() {
    }

    public static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate RSA key pair", ex);
        }
    }

    public static String signToken(PrivateKey privateKey, String kid, String issuer, Instant now) {
        return signToken(privateKey, kid, issuer, now, now.plusSeconds(300), now.minusSeconds(5), "profile email");
    }

    public static String signToken(PrivateKey privateKey,
                                   String kid,
                                   String issuer,
                                   Instant issuedAt,
                                   Instant expiresAt,
                                   Instant notBefore,
                                   String scope) {
        try {
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .subject("user-123")
                    .issueTime(Date.from(issuedAt))
                    .claim("preferred_username", "demo-user");

            if (issuer != null) {
                claimsBuilder.issuer(issuer);
            }
            if (expiresAt != null) {
                claimsBuilder.expirationTime(Date.from(expiresAt));
            }
            if (notBefore != null) {
                claimsBuilder.notBeforeTime(Date.from(notBefore));
            }
            if (scope != null) {
                claimsBuilder.claim("scope", scope);
            }

            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(JOSEObjectType.JWT);
            if (kid != null) {
                headerBuilder.keyID(kid);
            }

            SignedJWT jwt = new SignedJWT(headerBuilder.build(), claimsBuilder.build());
            jwt.sign(new RSASSASigner(privateKey));
            return jwt.serialize();
        } catch (JOSEException ex) {
            throw new IllegalStateException("Failed to sign JWT", ex);
        }
    }

    public static String signExpiredToken(PrivateKey privateKey, String kid, String issuer, Instant now) {
        return signToken(privateKey, kid, issuer, now.minusSeconds(360), now.minusSeconds(60), now.minusSeconds(360), "profile email");
    }

    public static String signNotYetActiveToken(PrivateKey privateKey, String kid, String issuer, Instant now) {
        return signToken(privateKey, kid, issuer, now, now.plusSeconds(300), now.plusSeconds(120), "profile email");
    }

    public static String signTokenWithoutKid(PrivateKey privateKey, String issuer, Instant now) {
        return signToken(privateKey, null, issuer, now, now.plusSeconds(300), now.minusSeconds(5), "profile email");
    }

    public static String signTokenWithoutIssuer(PrivateKey privateKey, String kid, Instant now) {
        return signToken(privateKey, kid, null, now, now.plusSeconds(300), now.minusSeconds(5), "profile email");
    }

    public static String signTokenWithoutExpiration(PrivateKey privateKey, String kid, String issuer, Instant now) {
        return signToken(privateKey, kid, issuer, now, null, now.minusSeconds(5), "profile email");
    }

    public static String rsaJwksJson(String kid, RSAPublicKey publicKey) {
        String n = base64UrlUInt(publicKey.getModulus());
        String e = base64UrlUInt(publicKey.getPublicExponent());

        return """
                {
                  "keys": [
                    {
                      "kty": "RSA",
                      "kid": "%s",
                      "use": "sig",
                      "alg": "RS256",
                      "n": "%s",
                      "e": "%s"
                    }
                  ]
                }
                """.formatted(kid, n, e);
    }

    public static String rsaJwksJson(String kid1, RSAPublicKey key1, String kid2, RSAPublicKey key2) {
        return """
                {
                  "keys": [
                    {
                      "kty": "RSA",
                      "kid": "%s",
                      "use": "sig",
                      "alg": "RS256",
                      "n": "%s",
                      "e": "%s"
                    },
                    {
                      "kty": "RSA",
                      "kid": "%s",
                      "use": "sig",
                      "alg": "RS256",
                      "n": "%s",
                      "e": "%s"
                    }
                  ]
                }
                """.formatted(
                kid1, base64UrlUInt(key1.getModulus()), base64UrlUInt(key1.getPublicExponent()),
                kid2, base64UrlUInt(key2.getModulus()), base64UrlUInt(key2.getPublicExponent())
        );
    }

    private static String base64UrlUInt(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
