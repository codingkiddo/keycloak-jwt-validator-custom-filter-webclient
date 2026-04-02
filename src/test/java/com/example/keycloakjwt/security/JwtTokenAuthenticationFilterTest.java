package com.example.keycloakjwt.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import com.example.keycloakjwt.security.filter.JwtTokenAuthenticationFilter;
import com.example.keycloakjwt.security.model.AuthenticatedJwtPrincipal;
import com.example.keycloakjwt.security.support.ClientConfigurations;

import jakarta.servlet.ServletException;

class JwtTokenAuthenticationFilterTest {

    private static final String ISSUER = "https://auth-dev.local/realms/platform";
    private static final String KID = "kid-1";

    private KeycloakJwksPublicKeyProvider publicKeyProvider;
    private JwtTokenAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        publicKeyProvider = Mockito.mock(KeycloakJwksPublicKeyProvider.class);
        ClientConfigurations clientConfigurations = Mockito.mock(ClientConfigurations.class);
        filter = new JwtTokenAuthenticationFilter(clientConfigurations, publicKeyProvider, List.of(ISSUER));
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void skipsAuthenticationWhenAuthorizationHeaderMissing() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/secure");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(publicKeyProvider, never()).getPublicKey(anyString(), anyString());
    }

    @Test
    void returns401WhenBearerTokenIsBlank() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/secure");
        request.addHeader("Authorization", "Bearer   ");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).contains("Bearer token is malformed");
    }

    @Test
    void returns401WhenTokenIsMalformed() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/secure");
        request.addHeader("Authorization", "Bearer not-a-jwt");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).contains("Bearer token is malformed");
    }

    @Test
    void returns401WhenIssuerClaimIsMissing() throws Exception {
        KeyPair pair = JwtTestUtils.generateRsaKeyPair();
        String token = JwtTestUtils.signTokenWithoutIssuer(pair.getPrivate(), KID, Instant.now());

        MockHttpServletRequest request = requestWithBearer(token);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).contains("Missing iss claim");
    }

    @Test
    void returns401WhenKidHeaderIsMissing() throws Exception {
        KeyPair pair = JwtTestUtils.generateRsaKeyPair();
        String token = JwtTestUtils.signTokenWithoutKid(pair.getPrivate(), ISSUER, Instant.now());

        MockHttpServletRequest request = requestWithBearer(token);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).contains("Missing kid in JWT header");
    }

    @Test
    void returns401WhenExpirationClaimIsMissing() throws Exception {
        KeyPair pair = JwtTestUtils.generateRsaKeyPair();
        String token = JwtTestUtils.signTokenWithoutExpiration(pair.getPrivate(), KID, ISSUER, Instant.now());
        when(publicKeyProvider.getPublicKey(ISSUER, KID)).thenReturn((RSAPublicKey) pair.getPublic());

        MockHttpServletRequest request = requestWithBearer(token);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).contains("Missing exp claim");
    }

    @Test
    void returns401WhenTokenIsExpired() throws Exception {
        KeyPair pair = JwtTestUtils.generateRsaKeyPair();
        String token = JwtTestUtils.signExpiredToken(pair.getPrivate(), KID, ISSUER, Instant.now());
        when(publicKeyProvider.getPublicKey(ISSUER, KID)).thenReturn((RSAPublicKey) pair.getPublic());

        MockHttpServletRequest request = requestWithBearer(token);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).contains("Token expired");
    }

    @Test
    void returns401WhenTokenIsNotYetActive() throws Exception {
        KeyPair pair = JwtTestUtils.generateRsaKeyPair();
        String token = JwtTestUtils.signNotYetActiveToken(pair.getPrivate(), KID, ISSUER, Instant.now());
        when(publicKeyProvider.getPublicKey(ISSUER, KID)).thenReturn((RSAPublicKey) pair.getPublic());

        MockHttpServletRequest request = requestWithBearer(token);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).contains("Token not active yet");
    }

    @Test
    void authenticatesValidTokenAndAddsScopeAuthorities() throws Exception {
        KeyPair pair = JwtTestUtils.generateRsaKeyPair();
        String token = JwtTestUtils.signToken(pair.getPrivate(), KID, ISSUER, Instant.now());
        when(publicKeyProvider.getPublicKey(ISSUER, KID)).thenReturn((RSAPublicKey) pair.getPublic());

        MockHttpServletRequest request = requestWithBearer(token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isInstanceOf(UsernamePasswordAuthenticationToken.class);
        assertThat(authentication.getAuthorities())
        .extracting(GrantedAuthority::getAuthority)
        .containsExactlyInAnyOrder("SCOPE_profile", "SCOPE_email");
        AuthenticatedJwtPrincipal principal = (AuthenticatedJwtPrincipal) authentication.getPrincipal();
        assertThat(principal.getSubject()).isEqualTo("user-123");
        assertThat(principal.getIssuer()).isEqualTo(ISSUER);
        assertThat(principal.getKid()).isEqualTo(KID);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    private MockHttpServletRequest requestWithBearer(String token) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/secure");
        request.addHeader("Authorization", "Bearer " + token);
        return request;
    }
}
