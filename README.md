# spring-boot-oauth2-pkce-demo

A single Spring Boot application that plays **both sides** of the OAuth 2.0 Authorization Code flow
with **PKCE** (RFC 7636):

* an **Authorization Server** (Spring Authorization Server) that refuses any authorization request
  arriving without a `code_challenge`, and
* a **public OAuth2 client** — no client secret — that logs in against that same server.

Users, registered clients, authorizations, consents and the client's own tokens all live in
**MySQL**. Every screen is rendered with **Thymeleaf**.

## Stack

| | |
|---|---|
| Spring Boot | 4.1.1 |
| Spring Security / Authorization Server | 7.1.1 |
| Java | 25 |
| Database | MySQL 9.6 (Docker) |
| Migrations | Flyway 12.4 |
| Templates | Thymeleaf 3.1 + `thymeleaf-extras-springsecurity` |
| Tests | JUnit 5 + Testcontainers |

## Running it

```bash
docker compose up -d      # MySQL 9.6 on localhost:3312
./mvnw spring-boot:run    # app on http://localhost:8080
```

Open <http://localhost:8080> and press **Sign in with PKCE**.

### Demo accounts

Seeded into MySQL on first start, passwords BCrypt-hashed:

| Username | Password | Authorities |
|---|---|---|
| `hendi` | `password` | `ROLE_ADMIN`, `ROLE_USER` |
| `itadmin` | `password` | `ROLE_USER` |

## What the flow looks like

```
 browser                     this app (:8080)
    │
    │ GET /oauth2/authorization/pkce-demo-client
    │──────────────────────────────▶  client generates code_verifier,
    │                                 sends SHA-256 as code_challenge
    │ 302 /oauth2/authorize?…&code_challenge=…&code_challenge_method=S256
    │──────────────────────────────▶  authorization server: not signed in
    │ 302 /login                                     (Thymeleaf form)
    │──────────────────────────────▶  JpaUserDetailsService checks MySQL
    │ 302 /oauth2/consent?…                          (Thymeleaf consent)
    │──────────────────────────────▶  user approves profile + email
    │ 302 /login/oauth2/code/…?code=…
    │──────────────────────────────▶  client POSTs code + code_verifier
    │                                 to /oauth2/token; server recomputes
    │                                 SHA-256 and compares
    │ 302 /dashboard
```

The **/dashboard** page shows the actual `code_verifier` and `code_challenge` used for your session,
plus the decoded ID token. **/tokens** shows the raw JWTs and the `/userinfo` response.

## How PKCE is enforced

The client is registered as a **public** client, so there is no secret to fall back on:

```java
RegisteredClient.withId(...)
    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
    .clientSettings(ClientSettings.builder()
            .requireProofKey(true)          // reject requests with no code_challenge
            .requireAuthorizationConsent(true)
            .build())
```

An authorization request without a challenge is rejected outright:

```
GET /oauth2/authorize?response_type=code&client_id=pkce-demo-client&scope=openid&state=abc

302 → …?error=invalid_request
      &error_description=OAuth%202.0%20Parameter%3A%20code_challenge
      &error_uri=https://datatracker.ietf.org/doc/html/rfc7636%23section-4.4.1
```

`PkceAuthorizationFlowTests` asserts exactly this, and also that a request *with* an `S256`
challenge is accepted and parked at the login page.

## Layout

```
src/main/java/id/my/hendisantika/oauth2pkcedemo/
├── config/
│   ├── AuthorizationServerConfig.java   filter chain 1 — /oauth2/**, /userinfo, JWKs, claims
│   ├── WebSecurityConfig.java           filter chain 2 — login form, oauth2Login, client registration
│   ├── DemoDataInitializer.java         seeds users + the PKCE client (idempotent)
│   └── DemoProperties.java              typed binding for the `app.*` properties
├── controller/
│   ├── HomeController.java              /, /login, /dashboard, /tokens
│   └── ConsentController.java           /oauth2/consent
├── entity|repository|service/           users + JpaUserDetailsService
└── security/
    ├── PkceAuditingAuthorizationRequestRepository.java   records the verifier/challenge
    └── PkceExchange.java

src/main/resources/db/migration/
├── V1_13092026_1256__create_user_tables.sql
├── V2_13092026_1257__create_oauth2_authorization_server_tables.sql
└── V3_13092026_1258__create_oauth2_authorized_client_table.sql
```

## Notes worth knowing

* **Two filter chains, one app.** Chain 1 (`@Order(1)`) matches only the authorization server
  endpoints; everything else falls through to chain 2. Both `formLogin` and `oauth2Login` register a
  default entry point, so chain 2 pins one explicitly — otherwise a protected page could bypass the
  PKCE flow and land on the raw login form.
* **No `issuer-uri` in `application.yaml`.** A properties-based registration with `issuer-uri` does
  OIDC discovery during startup, and here the provider being discovered is the app that has not
  finished starting. The `ClientRegistration` is therefore built in `WebSecurityConfig`.
* **Claims must be mutable collections.** The JDBC authorization store serialises claims through
  Jackson's polymorphic typing, whose allow-list rejects the immutable list `Stream.toList()`
  returns. `AuthorizationServerConfig` collects into an `ArrayList` for that reason.
* **Spring Boot 4 modularised auto-configuration.** `flyway-core` alone does nothing; the
  `spring-boot-flyway` module must be on the classpath too.
* **MySQL JDBC parameters.** The URL carries
  `preserveInstants=true&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true`, as the
  authorization server's own schema documentation requires, so token instants round-trip as UTC.
* **Signing keys are generated per boot.** Tokens do not survive a restart. A real deployment keeps
  a stable key.

## Tests

```bash
./mvnw test
```

Boots the application against a throwaway MySQL container (Testcontainers), so nothing but Docker
needs to be running.
