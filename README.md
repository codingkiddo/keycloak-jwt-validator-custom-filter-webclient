# Keycloak JWT Validator (Custom Filter + WebClient)

This project keeps the custom Spring Security filter style:

```java
.addFilterAfter(
    new JwtTokenAuthenticationFilter(
        clientConfigurations,
        keycloakJwksPublicKeyProvider,
        allowedIssuers
    ),
    UsernamePasswordAuthenticationFilter.class
)
```

and swaps only the JWKS fetch implementation from `RestTemplate` to `WebClient`.

## What it does

- validates bearer tokens in a custom `OncePerRequestFilter`
- accepts only configured issuers
- fetches Keycloak JWKS from `{issuer}/protocol/openid-connect/certs`
- extracts RSA public keys from `x5c` or `n` + `e`
- caches keys by `issuer + kid`
- refreshes JWKS on cache miss
- validates signature, `iss`, `exp`, and `nbf`

## Configure

Update `src/main/resources/application.yml`:

- set the real `spring.ssl.bundle.jks.keycloak-jwks.truststore.location`
- set `config.secapi.auth.allowed-issuers`

## Run

```bash
mvn clean test
mvn spring-boot:run
```

## Endpoints

- `GET /public/ping`
- `GET /api/secure` with `Authorization: Bearer <token>`

## Notes

- `spring-boot-starter-webflux` is included only to use `WebClient`
- the application itself still runs as a normal Spring MVC app
