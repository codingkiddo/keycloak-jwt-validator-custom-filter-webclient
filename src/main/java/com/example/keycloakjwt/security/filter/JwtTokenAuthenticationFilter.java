package com.example.keycloakjwt.security.filter;

import com.example.keycloakjwt.security.KeycloakJwksPublicKeyProvider;
import com.example.keycloakjwt.security.KeycloakJwtProperties;
import com.example.keycloakjwt.security.model.AuthenticatedJwtPrincipal;
import com.example.keycloakjwt.security.support.ClientConfigurations;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

    private static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(30);

    @SuppressWarnings("unused")
    private final ClientConfigurations clientConfigurations;
    private final KeycloakJwksPublicKeyProvider keycloakJwksPublicKeyProvider;
    private final Set<String> allowedIssuers;

    public JwtTokenAuthenticationFilter(ClientConfigurations clientConfigurations,
                                        KeycloakJwksPublicKeyProvider keycloakJwksPublicKeyProvider,
                                        List<String> allowedIssuers) {
        this.clientConfigurations = clientConfigurations;
        this.keycloakJwksPublicKeyProvider = keycloakJwksPublicKeyProvider;
        this.allowedIssuers = allowedIssuers == null ? Set.of() : allowedIssuers.stream()
                .map(KeycloakJwtProperties::normalizeIssuer)
                .collect(Collectors.toUnmodifiableSet());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(7).trim();
        if (!StringUtils.hasText(token)) {
            unauthorized(response, "Bearer token is malformed");
            return;
        }

        try {
            SignedJWT signedJwt = SignedJWT.parse(token);
            String issuer = extractIssuer(signedJwt);
            if (!allowedIssuers.contains(issuer)) {
                throw new BadJwtException("Untrusted issuer: " + issuer);
            }

            String kid = signedJwt.getHeader().getKeyID();
            if (!StringUtils.hasText(kid)) {
                throw new BadJwtException("Missing kid in JWT header");
            }

            String alg = signedJwt.getHeader().getAlgorithm() == null ? null : signedJwt.getHeader().getAlgorithm().getName();
            if (!StringUtils.hasText(alg) || !(alg.startsWith("RS") || alg.startsWith("PS"))) {
                throw new BadJwtException("Unsupported JWT algorithm: " + alg);
            }

            RSAPublicKey publicKey = keycloakJwksPublicKeyProvider.getPublicKey(issuer, kid);
            if (!signedJwt.verify(new RSASSAVerifier(publicKey))) {
                throw new BadJwtException("Invalid token signature");
            }

            Map<String, Object> claims = signedJwt.getJWTClaimsSet().getClaims();
            validateTemporalClaims(signedJwt);

            AuthenticatedJwtPrincipal principal = new AuthenticatedJwtPrincipal(
                    signedJwt.getJWTClaimsSet().getSubject(),
                    issuer,
                    kid,
                    claims
            );

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    principal,
                    token,
                    authoritiesFromClaims(claims)
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        } catch (ParseException ex) {
            SecurityContextHolder.clearContext();
            unauthorized(response, "Bearer token is malformed");
        } catch (JOSEException | BadJwtException ex) {
            SecurityContextHolder.clearContext();
            unauthorized(response, ex.getMessage());
        }
    }

    private String extractIssuer(SignedJWT signedJwt) throws ParseException {
        String issuer = signedJwt.getJWTClaimsSet().getIssuer();
        if (!StringUtils.hasText(issuer)) {
            throw new BadJwtException("Missing iss claim");
        }
        return KeycloakJwtProperties.normalizeIssuer(issuer);
    }

    private void validateTemporalClaims(SignedJWT signedJwt) throws ParseException {
        Instant now = Instant.now();

        if (signedJwt.getJWTClaimsSet().getExpirationTime() == null) {
            throw new BadJwtException("Missing exp claim");
        }

        Instant expiresAt = signedJwt.getJWTClaimsSet().getExpirationTime().toInstant();
        if (now.isAfter(expiresAt.plus(DEFAULT_CLOCK_SKEW))) {
            throw new BadJwtException("Token expired");
        }

        if (signedJwt.getJWTClaimsSet().getNotBeforeTime() != null) {
            Instant notBefore = signedJwt.getJWTClaimsSet().getNotBeforeTime().toInstant();
            if (now.isBefore(notBefore.minus(DEFAULT_CLOCK_SKEW))) {
                throw new BadJwtException("Token not active yet");
            }
        }
    }

    private Collection<? extends GrantedAuthority> authoritiesFromClaims(Map<String, Object> claims) {
        Object scope = claims.get("scope");
        if (!(scope instanceof String scopeString) || scopeString.isBlank()) {
            return Collections.emptyList();
        }

        return Arrays.stream(scopeString.split("\\s+"))
                .filter(StringUtils::hasText)
                .map(value -> new SimpleGrantedAuthority("SCOPE_" + value))
                .collect(Collectors.toList());
    }

    private void unauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader("WWW-Authenticate",
                "Bearer error=\"invalid_token\", error_description=\"" + sanitize(message) + "\"");
    }

    private String sanitize(String message) {
        return message == null ? "Unauthorized" : message.replace("\"", "'");
    }
}
