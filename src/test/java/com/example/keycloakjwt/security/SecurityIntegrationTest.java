package com.example.keycloakjwt.security;

import com.example.keycloakjwt.api.SecureController;
import com.example.keycloakjwt.security.config.WebSecurityConfig;
import com.example.keycloakjwt.security.support.ClientConfigurations;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = SecurityIntegrationTest.TestApp.class)
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "config.secapi.auth.allowed-issuers=https://keycloak.example.com/realms/platform",
        "spring.ssl.bundle.jks.keycloak-jwks.truststore.location=file:/tmp/test-truststore.jks",
        "spring.ssl.bundle.jks.keycloak-jwks.truststore.password=changeit"
})
class SecurityIntegrationTest {

    private static final String ISSUER = "https://keycloak.example.com/realms/platform";
    private static final String KID = "kid-1";

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private KeycloakJwksPublicKeyProvider publicKeyProvider;

    @MockBean
    private ClientConfigurations clientConfigurations;

    @Test
    void returns401WhenAuthorizationHeaderMissing() throws Exception {
        mockMvc.perform(get("/api/secure"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void returns401WhenTokenIsMalformed() throws Exception {
        mockMvc.perform(get("/api/secure")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
                        Matchers.containsString("Bearer token is malformed")));
    }

    @Test
    void returns200WhenSignatureIsValid() throws Exception {
        KeyPair pair = JwtTestUtils.generateRsaKeyPair();
        String token = JwtTestUtils.signToken(pair.getPrivate(), KID, ISSUER, Instant.now());

        when(publicKeyProvider.getPublicKey(ISSUER, KID))
                .thenReturn((RSAPublicKey) pair.getPublic());

        mockMvc.perform(get("/api/secure")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.iss").value(ISSUER))
                .andExpect(jsonPath("$.kid").value(KID));
    }

    @Test
    void returns401WhenSignatureValidationFails() throws Exception {
        KeyPair signingPair = JwtTestUtils.generateRsaKeyPair();
        KeyPair wrongVerificationPair = JwtTestUtils.generateRsaKeyPair();

        String token = JwtTestUtils.signToken(signingPair.getPrivate(), KID, ISSUER, Instant.now());

        when(publicKeyProvider.getPublicKey(ISSUER, KID))
                .thenReturn((RSAPublicKey) wrongVerificationPair.getPublic());

        mockMvc.perform(get("/api/secure")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void returns401WhenIssuerIsNotAllowed() throws Exception {
        KeyPair pair = JwtTestUtils.generateRsaKeyPair();
        String token = JwtTestUtils.signToken(pair.getPrivate(), KID, "https://evil.example.com/realms/platform", Instant.now());

        mockMvc.perform(get("/api/secure")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void returns401WhenTokenIsExpired() throws Exception {
        KeyPair pair = JwtTestUtils.generateRsaKeyPair();
        String token = JwtTestUtils.signExpiredToken(pair.getPrivate(), KID, ISSUER, Instant.now());

        when(publicKeyProvider.getPublicKey(ISSUER, KID))
                .thenReturn((RSAPublicKey) pair.getPublic());

        mockMvc.perform(get("/api/secure")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
                        Matchers.containsString("Token expired")));
    }

    @SpringBootApplication(scanBasePackageClasses = SecureController.class)
    @Import({
            WebSecurityConfig.class,
            SecureController.class
    })
    static class TestApp {
    }
}
