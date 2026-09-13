# spring-boot-oauth2-pkce-demo

A single Spring Boot application that plays **both sides** of the OAuth 2.0 Authorization Code flow
with **PKCE** (RFC 7636):

* an **Authorization Server** (Spring Authorization Server) that refuses any authorization request
  arriving without a `code_challenge`, and
* two **OAuth2 clients** that log in against that same server — a **public** one with no secret at
  all, and a **confidential** one that keeps a secret and is *still* required to use PKCE.

Users, registered clients, authorizations, consents and the client's own tokens all live in
**MySQL**. Every screen is rendered with **Thymeleaf**.

![Landing page](docs/images/01-landing.png)

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
./mvnw spring-boot:run    # app on http://localhost:8080, plus https://localhost:8443 for mTLS
```

The second listener exists only for the mTLS page; everything else is on 8080. Its certificates are
generated in memory at startup and written to temp files for Tomcat to read, so nothing is committed
and nothing needs installing.

Open <http://localhost:8080> and press **Sign in with PKCE**.

### Demo accounts

Seeded into MySQL on first start, passwords BCrypt-hashed:

| Username | Password | Authorities |
|---|---|---|
| `hendi` | `password` | `ROLE_ADMIN`, `ROLE_USER` |
| `itadmin` | `password` | `ROLE_USER` |

### Registered clients

| Client | Authentication | PKCE | PAR | Grants | Refresh token |
|---|---|---|---|---|---|
| `pkce-demo-client` | none (public) | required | no | code, refresh, **device** | **no** on the code grant — see below |
| `pkce-confidential-client` | `client_secret_basic` | required | **yes** | code, refresh | yes, rotated on every use |
| `pkce-assertion-client` | **`private_key_jwt`** | n/a | n/a | client credentials | no |
| `pkce-mtls-client` | **`self_signed_tls_client_auth`** | n/a | n/a | client credentials | no |

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

## Screenshots

**1. Sign in** — the authorization server has parked the authorization request and needs to know who
you are. The `code_challenge` is already in the query string behind this redirect.

![Login form](docs/images/02-login.png)

**2. Approve access** — `requireAuthorizationConsent(true)` means the user decides which scopes the
client actually gets. `openid` is implied by an OIDC request and is never offered for approval.

![Consent screen](docs/images/03-consent.png)

**3. Dashboard** — the verifier and challenge that were really exchanged for this session, next to
the decoded ID token. The challenge travelled in the browser redirect; the verifier never left the
app until the token request.

![Dashboard showing the PKCE exchange and ID token claims](docs/images/04-dashboard.png)

**4. Tokens** — the authorization request URI as sent, plus the raw ID and access JWTs and the
`/userinfo` response.

![Raw tokens page](docs/images/05-tokens.png)

**5. Refresh** — signed in as the *public* client there is nothing to refresh, and the page says why
rather than hiding it.

![Refresh page explaining that a public client gets no refresh token](docs/images/06-refresh-public-client.png)

**6. Refresh** — signed in as the confidential client, `grant_type=refresh_token` returns a new
access token *and* a rotated refresh token.

![Refresh token grant showing before and after](docs/images/07-refresh-token-grant.png)

**7. Logout** — clearing the client's session and ending the session at the authorization server are
two different acts, with two buttons.

![Logout page contrasting local and RP-initiated logout](docs/images/08-logout.png)

**8. Device flow** — `/device` pretends to be a television. It is not signed in and does not need to
be.

![Device page before requesting a code](docs/images/09-device-start.png)

**9. Device flow** — the short code to type somewhere else, and the device polling `/oauth2/token`
on the interval the server asked for.

![Device showing a user code and polling](docs/images/10-device-polling.png)

**10. Device flow** — `/activate`, where the human types the code. This is the page
`verification_uri` points at.

![Activation page with the code pre-filled](docs/images/11-device-activate.png)

**11. Device flow** — the same consent screen as the browser flow, told which device code it is
approving.

![Consent screen naming the device code](docs/images/12-device-consent.png)

**12. Device flow** — the next poll returns tokens, and the device page updates itself.

![Device page showing the granted tokens](docs/images/13-device-approved.png)

**13. Introspect and revoke** — signed in as the confidential client, both operations are on offer.

![Introspection page with both operations](docs/images/14-introspect-start.png)

**14. Introspect** — a live token, described by the authorization server.

![Introspection of an active token](docs/images/15-introspect-active.png)

**15. Revoke** — the same token afterwards: `active: false`, and nothing else.

![Introspection of a revoked token](docs/images/16-introspect-revoked.png)

**16. Introspect** — signed in as the public client, introspection still works but revocation is not
offered, and the page says why.

![Introspection page for a public client session](docs/images/17-introspect-public-client.png)

**17. PAR** — two ways to start the same login, with and without pushing the request first.

![PAR page offering both sign-in routes](docs/images/18-par-start.png)

**18. PAR** — what the browser actually carried, against what it would have carried otherwise.

![Front-channel URL with and without PAR](docs/images/19-par-comparison.png)

**19. PAR** — the parameters that went over the back channel instead.

![The pushed request parameters](docs/images/20-par-pushed.png)

**20. DPoP** — the client makes a key, proves possession of it, and gets a token tied to it.

![DPoP page before running](docs/images/21-dpop-start.png)

**21. DPoP** — `token_type` is `DPoP`, and the token's `cnf.jkt` is the key's thumbprint.

![The key thumbprint matching the cnf claim](docs/images/22-dpop-binding.png)

**22. DPoP** — the same token three ways. Only the one accompanied by a proof from the bound key
works.

![Three attempts: 200, 401, 401](docs/images/23-dpop-attempts.png)

**23. Client assertions** — a client registered with no secret at all, only a pointer to its public
keys.

![Assertion client registration and published key](docs/images/24-assertion-registration.png)

**24. Client assertions** — a token for a valid assertion, `invalid_client` for the wrong key and
for an expired one.

![Three attempts: 200, 401, 401](docs/images/25-assertion-results.png)

**25. Client assertions** — the claims that make an assertion usable exactly once, at exactly one
endpoint.

![The assertion's claims](docs/images/26-assertion-claims.png)

**26. mTLS** — a client with no credential in the request at all, identified by its certificate.

![mTLS client registration](docs/images/27-mtls-registration.png)

**27. mTLS** — the same request twice; only the handshake differs, and the issued token carries the
certificate's thumbprint.

![Two attempts: 200 with cnf.x5t#S256, 302 without](docs/images/28-mtls-results.png)

## Refresh tokens and public clients

`/refresh` runs `grant_type=refresh_token` on demand — while the current access token is still
valid, which `RefreshTokenOAuth2AuthorizedClientProvider` would not do on its own.

The catch the demo makes visible: **Spring Authorization Server will not issue a refresh token to a
public client.** `OAuth2RefreshTokenGenerator` returns `null` when the client authenticates with
`ClientAuthenticationMethod.NONE` on the authorization code grant — a long-lived token in the hands
of a client that cannot keep a secret is what the OAuth 2.0 Security BCP warns against. That is why
there is a second, confidential client; PKCE applies to it just the same.

Refresh tokens are rotated (`reuseRefreshTokens(false)`), so replaying an old one fails — which is
how a server notices a stolen token.

## Logout

Two separate things, both on `/logout-demo`:

* **Local logout** — `POST /logout`. Spring Security clears the `SecurityContext`, invalidates the
  session, drops the cookie. The authorization server is never told.
* **RP-initiated logout** — the browser goes to `/connect/logout` with `id_token_hint` and a
  `post_logout_redirect_uri`, and the server ends *its* session. An unregistered redirect URI is
  rejected with `invalid_request`, so this cannot be abused as an open redirect.

After only a local logout the authorization server still considers the user signed in, so the next
authorization request completes without a prompt. Because this demo runs both roles in one
application on one session, either button clears both; split across two deployments the difference
is visible.

## Device authorization grant

`/device` runs RFC 8628 end to end against this same application, for the case where the client has
no keyboard and no browser:

1. The device posts `client_id` and `scope` to `/oauth2/device_authorization` and gets back a
   `device_code` it keeps, plus a short `user_code` it displays.
2. The human opens `/activate` on another device, types the code, signs in, and approves the scopes
   on the same consent screen the browser flow uses.
3. The device polls `/oauth2/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:device_code`. Until someone approves, that is HTTP
   400 `authorization_pending` — a normal step, not a failure. `slow_down` backs the interval off by
   five seconds.

Two things this demo had to work around, both worth knowing:

* **A public client cannot authenticate at the device endpoints out of the box.** Spring
  Authorization Server's `PublicClientAuthenticationConverter` returns early unless the request is a
  PKCE *token* request, yet both `/oauth2/device_authorization` and the device-code token request
  insist on an authenticated client — so a device is bounced to `/login` instead of being served
  JSON. `DeviceClientAuthenticationConverter` and `DeviceClientAuthenticationProvider` fill that gap,
  following the approach the reference documentation describes.
* **`openid` is rejected on this grant** with `invalid_scope`, because OpenID Connect is not defined
  over the device flow. The device gets an access token and never an ID token, so `/device` requests
  only `profile` and `email`.

The device *is* issued a refresh token here — the restriction that withholds one from a public client
applies to the authorization code grant, not to this one.

Denying (or mistyping a code) has no redirect URI to report back to, so the default response is a raw
JSON 400. The device verification endpoint is given an error handler that sends the human to
`/activate` with a readable message instead; the device still learns `access_denied` on its next poll.

## Introspection and revocation

`/introspect` calls both endpoints as the confidential client, since RFC 7662 and RFC 7009 each
require an authenticated caller — an open introspection endpoint would be a token oracle.

The interesting part is that the two are scoped differently:

| | Introspection (RFC 7662) | Revocation (RFC 7009) |
|---|---|---|
| Whose tokens? | **any** client's | only the caller's own |
| Someone else's token | described normally | `invalid_client`, HTTP 400 |
| Unknown token | `{"active": false}` | HTTP 200 |

So the page offers revocation only when the session's tokens belong to the client holding the
secret, and explains the asymmetry otherwise.

Both specs are deliberately uninformative about tokens that do not exist. An inactive token
introspects to exactly `{"active": false}` and nothing else — revoked, expired and never-issued are
indistinguishable — and revocation answers `200` either way. Neither endpoint can be used to probe
which tokens are real. Revoking then introspecting is what actually proves the revocation landed.

Revoking an access token stops that one token; revoking a refresh token invalidates the authorization
it came from, taking the access token with it.

## Pushed authorization requests

`/par` shows RFC 9126: the client posts the authorization request to `/oauth2/par` over a back
channel and gets a handle, so the browser carries only a client id and that handle.

Measured on a real login in this app:

```
with PAR     180 characters
without PAR  390 characters
```

Everything that disappeared — `scope`, `redirect_uri`, `state`, `nonce`, `code_challenge` — went
straight from client to server, authenticated. That is the actual point: PKCE protects the *code*
coming back, but does nothing for the request going out, so a front channel request is readable and
rewritable by anything the redirect passes through. After a push, the server already knows what was
asked for by the time the browser is involved. Sidestepping URL length limits is a bonus.

`PushedAuthorizationRequestResolver` wraps Spring's `DefaultOAuth2AuthorizationRequestResolver`:
it pushes the request, then swaps *only* the browser-visible URI, leaving state, the PKCE verifier
and the redirect URI untouched so the callback is handled by the usual machinery. Nothing downstream
knows PAR happened.

Two things to know:

* **PAR is off by default.** Spring Authorization Server only exposes `/oauth2/par` — and only
  advertises it in the discovery document — once
  `.pushedAuthorizationRequestEndpoint(...)` is applied to the configurer.
* **Only the confidential client can push.** The endpoint requires client authentication, and the
  public client has nothing to authenticate with, so it sends the request the ordinary way. The page
  offers both routes side by side.

The `request_uri` is single-use and short-lived; replaying a consumed one is refused with `400`, so
lifting it out of browser history buys nothing.

## Sender-constrained tokens (DPoP)

`/dpop` demonstrates RFC 9449. A bearer token is a password — whoever holds it wins. DPoP ties the
token to a key the client keeps, so every use of it must be signed.

The client generates a P-256 key pair, signs a proof (`typ: dpop+jwt`, public JWK in the header,
`htm`/`htu`/`jti`/`iat` in the claims), and sends it with the token request. What comes back is
`token_type: DPoP` carrying `cnf.jkt` — the thumbprint of that key.

Then `/api/me` is called three times with **exactly the same token**:

| Attempt | Result |
|---|---|
| Proof signed by the bound key | `200` |
| No proof — a stolen token as it would be presented | `401` |
| Proof signed by a *different* key | `401` |

Holding the token is not enough, and holding it plus *a* key is not enough either.

Notes:

* **Spring's OAuth2 client has no DPoP support**, so the proofs are built by hand with Nimbus. The
  demo uses the refresh token grant to obtain the bound token, since that leg needs nothing from the
  browser — threading a proof through the authorization code leg would mean rebuilding Spring's
  redirect handling.
* **`/api/**` accepts only DPoP.** `jwt()` is configured so the access token can be decoded, but
  that also installs the bearer filter — and a plain JWT filter would happily accept a DPoP-bound
  token presented as `Authorization: Bearer`, because nothing in it checks `cnf.jkt`. The chain sets
  a `bearerTokenResolver` that resolves nothing, which is what actually keeps bearer out. Verified:
  replaying a real `cnf`-bearing token as Bearer gets `401`.
* `ath` binds a resource-request proof to one specific token, and `htm`/`htu`/`jti` pin it to one
  method, one URL, and one use.

## JWT client assertions (private_key_jwt)

`/assertion` demonstrates RFC 7523. Instead of sending a shared secret on every call, the client
signs a short-lived JWT with a private key. The authorization server stores no secret for this
client at all — only the URL where its public keys are published:

```
clientAuthenticationMethod   private_key_jwt
jwkSetUrl                    http://localhost:8080/client-jwks.json
signing algorithm            RS256
grant                        client_credentials   (no user involved)
```

The page requests a token three times:

| Attempt | Result |
|---|---|
| Assertion signed with the published key | `200` + access token |
| Same claims, signed with a key the server has never seen | `401 invalid_client` |
| Right key, but `exp` already past | `401 invalid_client` |

The assertion's `iss` and `sub` are both the client id — it asserts its own identity, not a user's —
`aud` is the token endpoint so it cannot be replayed elsewhere, and `exp` keeps the window short.

One deviation worth knowing: **RFC 7523 makes `client_id` optional** on the request, since the
assertion already names the client, but Spring Authorization Server's
`JwtClientAssertionAuthenticationConverter` requires it and answers `invalid_request` without it.

The upside over a shared secret is that nothing confidential exists on the server side, nothing
confidential crosses the wire, and rotating the key means publishing a new JWK Set rather than
coordinating a secret with the operator.

## Certificate-bound tokens (mTLS)

`/mtls` demonstrates RFC 8705. The client presents a TLS client certificate and nothing in the
request body is a credential at all. The token that comes back carries `cnf.x5t#S256` — the SHA-256
of that certificate — so it only works over a connection presenting the same one.

The page sends the same form twice over `https://localhost:8443/oauth2/token`:

| Attempt | Result |
|---|---|
| Handshake presents the client certificate | `200`, and `cnf.x5t#S256` equals the certificate thumbprint |
| Identical request, no certificate offered | `302` to the login page — it never authenticated as a client |

Only the handshake differs. That is the appeal: the credential never appears in anything the
application layer can log or leak.

This is the one page that needed infrastructure rather than just code:

* **A second listener on 8443**, added as an extra Tomcat connector. Everything else stays on plain
  HTTP 8080, and the issuer is unchanged.
* **Certificate verification is `want`, not `need`.** A handshake with no certificate must still
  succeed, or the failing case would be a dropped connection rather than an OAuth refusal — which
  would demonstrate nothing about the protocol.
* **Certificates are generated at startup** (BouncyCastle, since the JDK has no public API for
  creating X.509 certificates) and written to temp files because Tomcat's SSL configuration takes
  keystore paths. Nothing is committed, and they are regenerated on every boot.
* **`self_signed_tls_client_auth`, not `tls_client_auth`** — the certificate is matched against the
  `x5c` chain in the client's published JWK Set, so there is no CA to stand up. `tls_client_auth`
  would need a real trust anchor and a registered subject DN.

It is the same idea as DPoP one layer down: DPoP proves key possession with a signed header and needs
nothing from the network, mTLS proves it with the transport and needs TLS to reach the application
intact.

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
│   ├── OAuth2LoginRequiredInterceptor.java  keeps form-login-only sessions off the demo pages
│   └── WebMvcConfig.java                registers that interceptor
├── controller/
│   ├── HomeController.java              /, /login, /dashboard, /tokens
│   ├── ConsentController.java           /oauth2/consent (browser and device flows)
│   ├── RefreshTokenController.java      /refresh
│   ├── LogoutDemoController.java        /logout-demo, /logout/rp-initiated
│   ├── DeviceFlowController.java        /device, /device/poll, /activate
│   ├── TokenAdminController.java        /introspect, /introspect/revoke
│   ├── PushedAuthorizationController.java  /par
│   ├── DpopController.java              /dpop
│   ├── ProtectedApiController.java      /api/me, DPoP-only resource server
│   ├── ClientAssertionController.java   /assertion
│   ├── ClientJwkSetController.java      /client-jwks.json, the client's public keys
│   ├── MtlsController.java              /mtls
│   └── MtlsJwkSetController.java        /mtls-jwks.json, the client's certificate
├── entity|repository/                   users
├── service/
│   ├── JpaUserDetailsService.java       authenticates against MySQL
│   ├── TokenRefreshService.java         runs the refresh_token grant on demand
│   ├── DeviceFlowService.java           drives RFC 8628 over HTTP
│   ├── TokenAdminService.java           introspects and revokes as the confidential client
│   ├── PushedAuthorizationRequestService.java  pushes to /oauth2/par
│   ├── DpopService.java                 signs proofs and proves a stolen token is useless
│   ├── ClientAssertionService.java      authenticates with a signed JWT, three ways
│   └── MtlsService.java                 calls the TLS endpoint with and without a certificate
└── security/
    ├── PkceAuditingAuthorizationRequestRepository.java   records the verifier/challenge
    ├── PkceExchange.java
    ├── TokenSnapshot.java               before/after view of a token pair
    ├── DeviceAuthorization.java         the device's half of RFC 8628
    ├── DevicePollResult.java            the states a polling device can be in
    ├── DeviceClientAuthentication*.java lets a public client use the device endpoints
    ├── RestartOAuth2LoginFilter.java    makes a second login in one session work
    ├── IntrospectionResult.java
    ├── RevocationResult.java
    ├── PushedAuthorizationRequest.java
    ├── PushedAuthorizationRequestResolver.java  pushes before the browser is redirected
    ├── DpopKeyPair.java                 generates the key and signs proofs
    ├── DpopDemoResult.java
    ├── ClientAssertionKey.java          signs RFC 7523 assertions
    ├── ClientAssertionAttempt.java
    ├── MtlsMaterial.java                generates the demo certificates and keystores
    └── MtlsAttempt.java

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
* **`authenticated()` is not the same as "logged in through the client".** Signing in at the
  authorization server's own `/login` form satisfies `authenticated()`, but leaves a
  `UsernamePasswordAuthenticationToken` in the session — and the demo pages need an
  `OAuth2AuthenticationToken` to read tokens off. `OAuth2LoginRequiredInterceptor` sends those
  sessions through the client flow instead of letting argument resolution fail with a 500.
* **One session cannot hold two logins.** Client and authorization server share a
  `SecurityContext`, so after a login it holds an `OAuth2AuthenticationToken` — and if a second
  authorization request starts from that session, the authorization server treats *that* as the end
  user. Spring Security 7 reads `auth_time` off a `FactorGrantedAuthority` that only an interactive
  login attaches, so minting the ID token fails with "authenticationTime cannot be null" and the user
  gets a 500. Reachable just by pressing a sign-in button twice. `RestartOAuth2LoginFilter` clears the
  session and starts the flow clean.
* **A session can outlive the tokens it refers to.** Authentication still looks valid after the
  authorized client row is gone, so the token pages would dereference a null.
  `AuthorizedClientRequiredInterceptor` sends those sessions back through the flow.
* **Signing keys are generated per boot.** Tokens do not survive a restart. A real deployment keeps
  a stable key.

## Tests

```bash
./mvnw test
```

Boots the application against a throwaway MySQL container (Testcontainers), so nothing but Docker
needs to be running.
