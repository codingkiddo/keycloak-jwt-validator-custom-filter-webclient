package com.example.keycloakjwt.api;

import com.example.keycloakjwt.security.KeycloakJwksPublicKeyProvider;
import com.example.keycloakjwt.security.JwtTestUtils;
import com.example.keycloakjwt.security.support.ClientConfigurations;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.test.web.servlet.MockMvc;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SecureController.class)
@Import(TestSecurityConfig.class)
class SecureControllerTest {

    private static final String ISSUER = "https://auth-dev.local/realms/platform";
    private static final String KID = "kid-123";

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ClientConfigurations clientConfigurations;

    @MockBean
    private KeycloakJwksPublicKeyProvider keycloakJwksPublicKeyProvider;

    @Test
    void ping_shouldReturnPong() throws Exception {
        mockMvc.perform(get("/public/ping"))
                .andExpect(status().isOk())
                .andExpect(content().string("pong"));
    }

    @Test
    void secure_shouldReturnPrincipalValues_whenGetPublicKeyIsMocked() throws Exception {
        KeyPair keyPair = JwtTestUtils.generateRsaKeyPair();
        String token = JwtTestUtils.signToken(keyPair.getPrivate(), KID, ISSUER, Instant.now());

        when(keycloakJwksPublicKeyProvider.getPublicKey(eq(ISSUER), eq(KID)))
                .thenReturn((RSAPublicKey) keyPair.getPublic());

        mockMvc.perform(get("/api/secure")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value("user-123"))
                .andExpect(jsonPath("$.iss").value(ISSUER))
                .andExpect(jsonPath("$.kid").value(KID));

        verify(keycloakJwksPublicKeyProvider).getPublicKey(eq(ISSUER), eq(KID));
    }

    @Test
    void secure_shouldReturnUnauthorized_whenNoToken() throws Exception {
        mockMvc.perform(get("/api/secure"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void secure_shouldReturnUnauthorized_whenGetPublicKeyRejectsToken() throws Exception {
        KeyPair keyPair = JwtTestUtils.generateRsaKeyPair();
        String token = JwtTestUtils.signToken(keyPair.getPrivate(), KID, ISSUER, Instant.now());

        when(keycloakJwksPublicKeyProvider.getPublicKey(eq(ISSUER), eq(KID)))
                .thenThrow(new BadJwtException("No public key found"));

        mockMvc.perform(get("/api/secure")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void secure_shouldReturnUnauthorized_whenIssuerNotAllowed() throws Exception {
        KeyPair keyPair = JwtTestUtils.generateRsaKeyPair();
        String token = JwtTestUtils.signToken(
                keyPair.getPrivate(),
                KID,
                "https://evil.local/realms/platform",
                Instant.now()
        );

        mockMvc.perform(get("/api/secure")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }
}
