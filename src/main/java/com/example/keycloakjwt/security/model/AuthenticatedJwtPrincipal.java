package com.example.keycloakjwt.security.model;

import java.util.Collections;
import java.util.Map;

public class AuthenticatedJwtPrincipal {

    private final String subject;
    private final String issuer;
    private final String kid;
    private final Map<String, Object> claims;

    public AuthenticatedJwtPrincipal(String subject, String issuer, String kid, Map<String, Object> claims) {
        this.subject = subject;
        this.issuer = issuer;
        this.kid = kid;
        this.claims = claims == null ? Map.of() : Collections.unmodifiableMap(claims);
    }

    public String getSubject() {
        return subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getKid() {
        return kid;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }
}
