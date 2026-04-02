package com.example.keycloakjwt.api;

import com.example.keycloakjwt.security.model.AuthenticatedJwtPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class SecureController {

    @GetMapping("/api/secure")
    public Map<String, Object> secure(Authentication authentication) {
        AuthenticatedJwtPrincipal principal = (AuthenticatedJwtPrincipal) authentication.getPrincipal();
        return Map.of(
                "sub", principal.getSubject(),
                "iss", principal.getIssuer(),
                "kid", principal.getKid()
        );
    }

    @GetMapping("/public/ping")
    public String ping() {
        return "pong";
    }
}
