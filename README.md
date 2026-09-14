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
| `pkce-exchange-client` | `client_secret_basic` | n/a | n/a | **token exchange**, client credentials | no |
| `pkce-ciba-client` | `client_secret_basic` | n/a | n/a | **CIBA** | no |
| `pkce-fapi-client` | `private_key_jwt` | required | n/a | code, refresh | yes, rotated, certificate-bound |
| `pkce-code-binding-client` | none (public) | required | n/a | code | no |
| `pkce-mixup-client` | none (public) | required | n/a | code | no |
| `pkce-registrar-client` | `client_secret_basic` | n/a | n/a | client credentials | no |
| `pkce-relay-client` | `client_secret_basic` | n/a | n/a | **token exchange**, client credentials | no |
| `pkce-mtls-refresh-client` | **`self_signed_tls_client_auth`** | n/a | n/a | **device**, refresh | yes, rotated, certificate-bound |
| `pkce-freshness-client` | none (public) | required | no | code | no |
| `pkce-silent-client` | none (public) | required | no | code | no |
| `pkce-request-uri-client` | `client_secret_basic` | required | **yes** | code | no |
| `pkce-rar-client` | `client_secret_basic` | required | **yes** | code | no |
| `pkce-dpop-nonce-client` | none (public) | required | no | code | no |
| `pkce-jarm-client` | none (public) | required | no | code | no |
| `pkce-jarm-ec-client` | none (public) | required | no | code | no |
| `pkce-jarm-none-client` | none (public) | required | no | code | no |
| `pkce-jarm-encrypted-client` | none (public) | required | no | code | no |
| `pkce-jarm-gcm-client` | none (public) | required | no | code | no |
| `pkce-jarm-unsupported-enc-client` | none (public) | required | no | code | no |
| `pkce-jar-ps-client` | none (public) | required | no | code | no |
| `pkce-jar-oaep512-client` | none (public) | required | no | code | no |
| `pkce-jar-rsa15-client` | none (public) | required | no | code | no |
| `pkce-jar-gcm-client` | none (public) | required | no | code | no |
| `pkce-jar-unsupported-enc-client` | none (public) | required | no | code | no |
| `pkce-jar-enc-only-client` | none (public) | required | no | code | no |
| `pkce-jar-none-client` | none (public) | required | no | code | no |
| `pkce-jar-none-strict-client` | none (public) | required | no | code | no |
| `pkce-par-required-client` | `client_secret_basic` | required | **required** | code | no |
| `pkce-fetched-request-client` | `client_secret_basic` | required | no | code | no |
| `pkce-jar-es-client` | none (public) | required | no | code | no |

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

**28. Token exchange** — a broad user token, and a service that wants a narrow one.

![Token exchange starting point](docs/images/29-exchange-start.png)

**29. Token exchange** — impersonation: `sub` is still the user, scope is down to `api.read`, and
nothing records the service.

![Impersonation result](docs/images/30-exchange-impersonation.png)

**30. Token exchange** — delegation: the same, plus an `act` claim naming who is acting.

![Delegation result with an act claim](docs/images/31-exchange-delegation.png)

**31. Token exchange** — a service cannot exchange its way past its own registration.

![Over-scoped exchange refused with invalid_scope](docs/images/32-exchange-refused.png)

**32. RAR** — asking for a specific payment rather than a `payments` scope.

![Rich authorization request page](docs/images/33-rar-request.png)

**33. RAR** — the consent screen names the amount and the creditor, not a category.

![Consent showing the specific payment](docs/images/34-rar-consent.png)

**34. RAR** — and the issued token carries it, so a resource server does not have to take the
client's word.

![authorization_details in the issued token](docs/images/35-rar-granted.png)

**35. RAR** — a type the server does not implement is refused at the push, before anyone is asked to
approve it.

![invalid_authorization_details](docs/images/36-rar-refused.png)

**36. CIBA** — the client names the user it wants and supplies a message they will recognise.

![Backchannel authentication request](docs/images/37-ciba-request.png)

**37. CIBA** — an `auth_req_id` and a polling interval. No redirect happened, and none will.

![Client polling for the outcome](docs/images/38-ciba-polling.png)

**38. CIBA** — the user's device, showing the same message so they can check it before approving.

![The approval screen](docs/images/39-ciba-approve.png)

**39. CIBA** — the next poll returns a token.

![Approved, with an access token](docs/images/40-ciba-granted.png)

**40. Step-up** — after a password login the token says one factor.

![acr loa:1, amr pwd](docs/images/41-stepup-loa1.png)

**41. Step-up** — asking for a higher level stops the authorization endpoint and collects the
missing factor.

![The step-up prompt](docs/images/42-stepup-prompt.png)

**42. Step-up** — the new token records both the level and the methods that reached it.

![acr loa:2, amr pwd and otp](docs/images/43-stepup-loa2.png)

**43. JAR** — the authorization request, and the same request signed.

![The request parameters and the signed object](docs/images/44-jar-request-object.png)

**44. JAR** — four ways to send it, only one of which works.

![Valid, tampered, corrupted and foreign-signed](docs/images/45-jar-outcomes.png)

**45. FAPI 2.0** — the profile's server requirements, checked against the running configuration.

![Server requirements, all passing](docs/images/46-fapi-server.png)

**46. FAPI 2.0** — the two it does not meet, stated rather than omitted, and the one the profile
stopped asking for.

![The failing and not-applicable requirements](docs/images/47-fapi-failures.png)

**47. FAPI 2.0** — per client: one built to the profile, the rest deliberately not.

![A failing client beside a passing one](docs/images/48-fapi-clients.png)

**48. Code binding** — two runs of the same flow, one naming a key and one not.

![The code binding page before a run](docs/images/49-code-binding-start.png)

**49. Code binding** — one authorization code, redeemed four ways. The first two attempts hold the
code *and* the PKCE verifier and are still refused.

![Four attempts, two refused, one issued, one replayed](docs/images/50-code-binding-bound.png)

**50. Code binding** — the same flow without `dpop_jkt`: the code redeems with no proof at all.

![An unbound code redeemed with nothing](docs/images/51-code-binding-unbound.png)

**51. Mix-up** — two authorization servers, one of them the attacker's, and a client that has to
work out which one answered.

![The mix-up cast](docs/images/52-mixup-cast.png)

**52. Mix-up** — a client that does not read `iss` hands the code and the PKCE verifier to the
attacker, who redeems them at the honest server.

![The attacker holding a token for the user](docs/images/53-mixup-stolen.png)

**53. Mix-up** — the same attack against a client that does read it. One comparison, made before
the token request.

![The mismatch caught and the flow abandoned](docs/images/54-mixup-detected.png)

**54. Metadata** — two documents describing one server, and what each says that the other does not.

![The two metadata documents compared](docs/images/55-metadata-two-documents.png)

**55. Metadata** — the RFC 8414 document field by field, with the requirement level and the
specification that registered each one.

![The published document field by field](docs/images/56-metadata-fields.png)

**56. Metadata** — a client reading it, and the issuer check that decides whether it may.

![Discovery accepted and rejected](docs/images/57-metadata-discovery.png)

**57. Registration** — the client metadata a caller sends, and where it sends it.

![The registration request](docs/images/58-registration-request.png)

**58. Registration** — six requests: one registers a client, five are refused, and the refusals are
the interesting part.

![Six registration requests](docs/images/59-registration-attempts.png)

**59. Registration** — what came back, and what the server decided on the new client's behalf.

![The issued credentials and the imposed settings](docs/images/60-registration-result.png)

**60. Revocation on logout** — the page asks for the confidential client, because RFC 7009 only
lets a client revoke tokens it was itself issued.

![The revocation page before a run](docs/images/61-revocation-sign-in.png)

**61. Revocation on logout** — logged out, session gone, and the refresh token still minting new
access tokens.

![Tokens surviving a logout](docs/images/62-revocation-without.png)

**62. Revocation on logout** — the same logout with RFC 7009 alongside it.

![Tokens revoked on logout](docs/images/63-revocation-with.png)

**63. Back-channel logout** — the receiving endpoint, one per client registration.

![The back-channel logout page](docs/images/64-backchannel-start.png)

**64. Back-channel logout** — six logout tokens, five of which break one rule each.

![Six logout tokens](docs/images/65-backchannel-tokens.png)

**65. Back-channel logout** — the session ended, and the token that ended it.

![The session ended and the logout token](docs/images/66-backchannel-session.png)

**66. Front-channel logout** — one URI per client, and only the one that asked for it is told which
session.

![The front-channel targets](docs/images/67-frontchannel-targets.png)

**67. Front-channel logout** — the whole of what the server renders: iframes, and nothing else.

![The logout document](docs/images/68-frontchannel-document.png)

**68. Front-channel logout** — the same URIs without cookies, and one that never arrives. All
indistinguishable from where the server is standing.

![The cookie-less probes](docs/images/69-frontchannel-probes.png)

**69. Session management** — what the session state is computed from.

![The session state inputs](docs/images/70-session-state.png)

**70. Session management** — the two iframes talking, with no request reaching the server.

![unchanged](docs/images/71-session-unchanged.png)

**71. Session management** — and after something changed the session at the provider.

![changed](docs/images/72-session-changed.png)

**72. Token exchange** — impersonation refused, because the user's token says who may act.

![Impersonation refused by may_act](docs/images/73-mayact-impersonation.png)

**73. Token exchange** — delegation by the named service, and the same exchange by another.

![Delegation allowed and refused](docs/images/74-mayact-delegation.png)

**74. Refresh binding** — a DPoP-bound access token *and* a refresh token, issued to a client with
no credentials.

![What the device was issued](docs/images/75-refresh-binding-issued.png)

**75. Refresh binding** — the wrong key is refused, no key at all is not, and afterwards the right
key is refused too.

![Three refresh attempts](docs/images/76-refresh-binding-attempts.png)

**76. mTLS refresh** — a certificate-bound access token and a refresh token, issued over the TLS
listener.

![What the device was issued](docs/images/77-mtls-refresh-issued.png)

**77. mTLS refresh** — the same refresh token spent three ways: a stranger's certificate, none at
all, and the registered one.

![Three refresh attempts over three connections](docs/images/78-mtls-refresh-attempts.png)

**78. ID token binding** — the session's own ID token, presented five ways. Two substitutions are
caught; two are not.

![Five ways to present an ID token](docs/images/79-idtoken-five-ways.png)

**79. ID token binding** — what `at_hash` would have contained, and that the ID token carries
neither hash.

![The claim that is not there](docs/images/80-idtoken-missing-at-hash.png)

**80. Step-up challenge** — the resource server refuses a token that was not earned strongly enough,
and names the level it wants.

![The RFC 9470 challenge](docs/images/81-stepup-challenge.png)

**81. Step-up challenge** — the same call after the step-up. Same client, same endpoint, same user.

![The loop closes](docs/images/82-stepup-loop-closed.png)

**82. Freshness** — `auth_time`, and what each `max_age` would mean for the session you are sitting
on.

![auth_time and the max_age decisions](docs/images/83-freshness-session.png)

**83. Freshness** — the same question asked three ways. One is honoured, one is not needed, one is
ignored.

![Three ways of asking](docs/images/84-freshness-three-ways.png)

**84. Silent authentication** — `prompt=none` asked five times, and answered five times without a
screen.

![Five questions, no screens](docs/images/85-silent-auth-five-questions.png)

**85. Silent authentication** — the `login_required` Spring Authorization Server implements and
never reaches.

![Reading the silent authentication page](docs/images/86-silent-auth-reading.png)

**86. request_uri** — what a pushed reference is made of: a prefix, a random part, and its own
expiry.

![The anatomy of a request_uri](docs/images/87-request-uri-anatomy.png)

**87. request_uri** — the same reference spent five ways. One code, and after four of them the
server is holding nothing.

![Five ways of spending it](docs/images/88-request-uri-five-ways.png)

**88. RAR enforcement** — what the token says was granted: which payment, of how much, to whom.

![The granted authorization detail](docs/images/89-rar-granted-detail.png)

**89. RAR enforcement** — five payment instructions held against that grant. Two accepted, and they
are the same payment.

![Five instructions](docs/images/90-rar-five-instructions.png)

**90. DPoP nonce** — the key, and the token bound to it.

![The key and the token](docs/images/91-dpop-nonce-binding.png)

**91. DPoP nonce** — five calls to a resource that demands a nonce. Refused, handed one, accepted.

![Five calls](docs/images/92-dpop-nonce-five-calls.png)

**92. Signed introspection** — the same question four ways: unsigned JSON, and three signed answers
each addressed to whoever asked.

![Four answers](docs/images/93-introspection-four-answers.png)

**93. Signed introspection** — the JWT, and the RFC 7662 object inside it.

![The signed response](docs/images/94-introspection-signed-response.png)

**94. JARM** — the same authorization asked for seven ways. Four answers are signed, one is tampered
with, and two arrive in the clear.

![Seven answers](docs/images/95-jarm-seven-answers.png)

**95. JARM** — inside the signed answers: a code and a refusal, each with `iss`, `aud` and `exp`.

![The signed claims](docs/images/96-jarm-signed-claims.png)

**96. JARM** — the three deliveries: after the hash, in a form the browser posts, and a mode this
server does not read.

![The delivery modes](docs/images/97-jarm-delivery-modes.png)

**97. JARM algorithms** — three clients that differ in one setting. Two are honoured; one cannot be.

![Three registrations](docs/images/98-jarm-alg-registrations.png)

**98. JARM algorithms** — the two keys the server publishes, and the `kid` that tells them apart.

![The published keys](docs/images/99-jarm-alg-keys.png)

**99. JARM encryption** — the same answer signed, and signed then encrypted: three parts against
five.

![A JWS and a JWE](docs/images/100-jarm-enc-jws-vs-jwe.png)

**100. JARM encryption** — what stays readable, and what is inside once the client decrypts it.

![The JWE header](docs/images/101-jarm-enc-header.png)

**101. JARM content encryption** — three registrations differing in one word, and the shapes they
produce.

![Three registrations](docs/images/102-jarm-enc-method-shapes.png)

**102. JARM content encryption** — why CBC pads and GCM does not.

![Reading the shapes](docs/images/103-jarm-enc-method-reading.png)

**103. Request object encryption** — the same request three ways, and what each leaves readable in
the URL.

![Three request objects](docs/images/104-jar-enc-three-objects.png)

**104. Request object encryption** — why the signature is still checked, and which way the keys
point.

![Reading the request objects](docs/images/105-jar-enc-reading.png)

**105. Request object signing algorithm** — five request objects, and the two the server agreed in
advance to accept.

![Five request objects](docs/images/106-jar-alg-five-objects.png)

**106. Request object signing algorithm** — why a valid signature is refused, and why `alg: none`
never reaches the question.

![Reading the algorithms](docs/images/107-jar-alg-reading.png)

**107. Request object encryption algorithm** — six request objects, and the two refusals the
registration spec would have allowed.

![Six request objects](docs/images/108-jar-enc-alg-six-objects.png)

**108. Request object encryption algorithm** — where this server departs from the spec, and where it
follows it.

![Reading the algorithms](docs/images/109-jar-enc-alg-reading.png)

**109. Request object content encryption** — six request objects, and the shapes that tell CBC and
GCM apart from outside.

![Six request objects](docs/images/110-jar-enc-method-six-objects.png)

**110. Request object content encryption** — the spec's own default, and the registration it says
cannot exist.

![Reading the methods](docs/images/111-jar-enc-method-reading.png)

**111. Unsigned request objects** — six request objects, five of them carrying no signature, and the
three reasons the refused ones were refused.

![Six request objects](docs/images/112-jar-none-six-objects.png)

**112. Unsigned request objects** — what is left doing the work once the signature is gone.

![Reading the unsigned objects](docs/images/113-jar-none-reading.png)

**113. Requiring request objects** — the same four requests under both settings of the server-wide
switch, and what the documents said each time.

![The same four requests, both ways](docs/images/114-jar-required-both-ways.png)

**114. Requiring request objects** — why the first row is the attack the section is named after.

![Reading the switch](docs/images/115-jar-required-reading.png)

**115. Requiring request objects, one client at a time** — two clients registered while you watch,
and the six requests that follow.

![Six requests](docs/images/116-jar-client-required-six-requests.png)

**116. Requiring request objects, one client at a time** — what the registration endpoint had to be
taught, and two things it quietly did not honour.

![Reading the client setting](docs/images/117-jar-client-required-reading.png)

**117. Requiring pushed requests** — five ways to start an authorization request, and the one that
works.

![Five requests](docs/images/118-par-required-five-requests.png)

**118. Requiring pushed requests** — why a signed request object is not a pushed one.

![Reading the PAR lock](docs/images/119-par-required-reading.png)

**119. Requiring pushed requests, server-wide** — the same four requests under both settings, with
the published document and the profile row read at each turn.

![The same four requests, both ways](docs/images/120-par-server-required-both-ways.png)

**120. Requiring pushed requests, server-wide** — why this is the row the FAPI page could not pass.

![Reading the server-wide lock](docs/images/121-par-server-required-reading.png)

**121. request_uri metadata** — what the documents say, what silence would have said, and four ways
of pointing at a request object.

![Four ways](docs/images/122-request-uri-metadata-four-ways.png)

**122. request_uri metadata** — one parameter, two unrelated features, and which check refuses which.

![Reading the metadata](docs/images/123-request-uri-metadata-reading.png)

**123. require_request_uri_registration** — four URLs under both settings, and the one row the
setting is the whole difference for.

![Four URLs, both ways](docs/images/124-request-uri-registration-both-ways.png)

**124. require_request_uri_registration** — what the registered list buys, and the checks that do not
depend on it.

![Reading the registration requirement](docs/images/125-request-uri-registration-reading.png)

**125. request_uris** — a list registered through the registration endpoint, echoed back, and the
four URLs measured against it.

![The registered list](docs/images/126-request-uris-registration.png)

**126. request_uris** — why the fragment counts, and why an empty list is a list.

![Reading the list](docs/images/127-request-uris-reading.png)

**127. request_object_signing_alg_values_supported** — the three lists, and five request objects
measured against them.

![Five request objects](docs/images/128-jar-alg-values-five-objects.png)

**128. request_object_signing_alg_values_supported** — why being on the list is not permission.

![Reading the lists](docs/images/129-jar-alg-values-reading.png)

**129. request_object_encryption_alg_values_supported** — the published keys beside the list, and
five objects that each have two of the three things needed.

![The keys and the five objects](docs/images/130-jar-enc-alg-values-keys.png)

**130. request_object_encryption_alg_values_supported** — why the list cannot stop a client picking
the wrong key.

![Reading the list](docs/images/131-jar-enc-alg-values-reading.png)

**131. request_object_encryption_enc_values_supported** — every advertised pair, twice over, and the
single cell each client may occupy.

![Two grids](docs/images/132-jar-enc-method-values-grids.png)

**132. request_object_encryption_enc_values_supported** — why two lists multiply and a registration
does not.

![Reading the grids](docs/images/133-jar-enc-method-values-reading.png)

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

## Session management (the OP iframe)

`/session-management` answers "is the user still signed in at the provider?" without a single
request reaching it. The provider serves a page, the client embeds it in a hidden iframe, and the two
talk by `postMessage`.

The value they compare is `session_state`, returned on the authorization response and computed as
section 3.2's own pseudo-code has it:

```
SHA-256(client_id + " " + origin + " " + OP browser state + " " + salt) + "." + salt
```

The salt travels with the value so the browser can redo the sum; the OP browser state is a cookie at
the provider's origin, which is why the iframe has to be loaded *from* the provider. The client posts
`"<client_id> <session_state>"` and gets back one of three words:

| Answer | What a client does |
|---|---|
| `unchanged` | nothing |
| `changed` | re-authenticate with `prompt=none` to find out what happened |
| `error` | **not** re-authenticate — that is how the infinite loops start |

Notes:

* **Neither half exists in Spring.** Spring Authorization Server emits no `session_state` and serves
  no `check_session_iframe`; Spring Security's client has no field for the parameter and drops it, as
  it dropped [`iss`](#mix-up-attack-defence-iss). Both are written out here, and both metadata
  documents now advertise the iframe.
* **The cookie must be readable by script**, since the iframe recomputes the hash in the browser. It
  is only a random value, but a non-`HttpOnly` cookie is a decision rather than an oversight.
* **Origin is not enough on its own.** The client and provider share an origin here, so anything else
  on the page can post to the same window — a browser extension was doing exactly that while this
  page was being written, and every one of its messages was being read as an answer. The RP script
  checks the source frame as well, and ignores anything that is not one of the three defined words.
* **Section 5.1 is unusually frank.** Browsers blocking third-party content can leave the iframe
  unable to read that cookie, in which case it answers `changed` every time and a conforming client
  re-authenticates every time, "resulting in infinite loops of re-authentications". The same
  paragraph notes that [back-channel logout](#back-channel-logout) is not affected.
* It works in this demo for the reason it usually does not: client and provider share an origin, so
  the iframe is first-party and the cookie is there.

## Front-channel logout

`/frontchannel-logout` is the other way of telling several clients that a session ended: instead of
the server calling each one, it renders a page of hidden iframes and lets the browser load them. Each
arrives at a client carrying *that client's* cookies — the one thing a server-to-server call can
never do, and the reason this mechanism fails quietly.

The page builds the document, renders it for real (the iframes end your session as they load), and
then fetches the same URIs from the server, without cookies:

| Request | Status | Answer |
|---|---|---|
| A client's URI, no cookie attached | `200` | `no session to end` |
| The other client's URI, no cookie | `200` | `no session to end` |
| A host that refuses the connection | — | the request never arrived |

Nothing there is malformed. The clients simply cannot tell who is asking, end nothing, and answer
`200` — and the last one is never delivered at all. **None of which the server can see**: it rendered
an iframe. A logout that worked, one that silently did nothing, and one that never arrived are the
same picture from where it stands.

Notes:

* **Neither half exists in Spring.** Spring Authorization Server renders no logout iframes and holds
  no `frontchannel_logout_uri`; Spring Security has no endpoint to receive one. Both sides are
  written out here — compare [back-channel logout](#back-channel-logout), where Spring Security had
  the receiving half already.
* **Only a client that registers `frontchannel_logout_session_required` is told which session.** It
  gets `iss` and `sid` on the query string; one that does not has to guess, usually by ending
  whatever session the cookie identifies — wrong the moment a user has two.
* **Third-party cookies are what this runs on.** Every iframe is a cross-site request to that client,
  and browsers have spent years making those arrive without cookies. It works in this demo only
  because every client shares an origin with the server.
* **The server had to allow framing.** Spring Security sends `X-Frame-Options: DENY` by default,
  which would stop the browser loading any of it.

Four logouts now, and only one of them can be checked: [local and RP-initiated](#logout) end one
session each, [revocation](#revocation-on-logout) ends the tokens,
[back-channel](#back-channel-logout) tells other clients and gets an answer, front-channel tells them
and does not.

## Back-channel logout

`/backchannel-logout` ends a session without the browser being involved at all. The authorization
server posts a signed **logout token** straight to the client, and the client ends the session it
names — which is the only way a logout can reach a client the user is not currently looking at.

The page sends six, five of which break one rule from OpenID Connect Back-Channel Logout §2.6:

| Logout token | Result |
|---|---|
| Without the `events` claim | `500` — see below |
| With a `nonce` | `400`, "nonce claim must not be present" |
| Addressed to another client | `400`, "aud claim value must include ClientRegistration#getClientId" |
| Naming neither `sub` nor `sid` | `400`, "sub and sid claims must not both be null" |
| Signed by a key the server does not publish | `400`, signature rejected |
| Valid | `200`, and the session is gone |

Notes:

* **Spring Authorization Server has no sending half.** Nothing in it mentions back-channel logout —
  no logout token, no `backchannel_logout_uri` on a registration, nothing sent when a session ends.
  `BackChannelLogoutService` mints and posts the tokens here, signed with the server's own key.
* **Spring Security has the receiving half, and it is one line.**
  `oidcLogout(oidc -> oidc.backChannel(...))` puts `/logout/connect/back-channel/{registrationId}` in
  place, validates the token against the issuer's published keys, and ends the matching sessions.
* **One refusal is a 500 and should be a 400.** `OidcBackChannelLogoutTokenValidator` means to report
  a missing `events` claim as an ordinary validation error — the line right after the check says so.
  It never gets there: reading the claim goes through `LogoutTokenClaimAccessor.getEvents()`, which
  asserts the claim is not null and throws first, and the filter turns that into a server error. The
  token is refused either way; the status is wrong for a request that is merely malformed.
* **The `sid` claim was already there.** Matching by session needs the ID token to carry one, and
  Spring Authorization Server issues it from its session registry — so the logout tokens name that
  same value rather than inventing one. Without a `sid`, a logout token can only name a subject and
  the client ends every session that user has.
* **Neither metadata document advertises it**, deliberately. `backchannel_logout_supported` would
  mean this server sends a logout token whenever a session ends; it sends them when this page asks.
  Advertising the flag would describe a server that does not exist.

Three logouts now, doing different work: [local and RP-initiated](#logout) end sessions,
[revocation](#revocation-on-logout) ends tokens, and back-channel logout is how the *other* clients
find out at all.

## Revocation on logout

`/logout-revocation` signs you out and then looks at what became of your tokens. Twice: once with
revocation, once without. The only difference between the runs is whether anything told the
authorization server.

Without it, after the session is gone:

| Step | Result |
|---|---|
| Introspect the access token | `active = true` |
| Introspect the refresh token | `active = true` |
| `grant_type=refresh_token` | a new access token, issued *after* the user signed out |

**Neither logout touches a token.** Spring Security's `/logout` clears the security context,
invalidates the session and drops the cookie. Spring Authorization Server's RP-initiated logout runs
a `SecurityContextLogoutHandler` and nothing else — that is the whole of
`OidcLogoutAuthenticationSuccessHandler`. Ending a session and ending an authorization are separate
acts, and nothing in OAuth connects them.

`RevokingLogoutHandler` is what connects them here: registered as a logout handler on `/logout` and
called explicitly before the RP-initiated redirect, so both of this application's sign-outs now
revoke. It revokes the refresh token first — that invalidates the authorization it came from, taking
the access token with it — then the access token explicitly, then drops the client's own stored copy.

Two things worth knowing:

* **A public client cannot clean up after itself.** RFC 7009 wants an authenticated client and only
  lets one revoke tokens it was itself issued, so revocation here runs as the confidential client.
  A client holding no credentials has no way to withdraw what it holds — the same asymmetry
  [introspection](#introspection-and-revocation) shows from the other side.
* **Short access token lifetimes are the other half of the answer.** Revocation closes the window;
  a short expiry decides how big the window is when revocation is impossible or never called.

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

Neither of them revokes anything on its own. Both do here, because
[`RevokingLogoutHandler`](#revocation-on-logout) was added to them.

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

What that answer is worth as *evidence* — signed, typed and addressed to the caller — is
[its own page](#signed-introspection-responses-rfc-9701).

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

What the reference itself is worth — how long it lasts, how often it works, and what happens when
it does not — is [its own page](#request_uri-expiry-and-one-time-use).

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

A proof says the caller holds the key, but not when they held it. Closing that window with a
server-supplied nonce is [its own page](#dpop-nonces).

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

## Token exchange

`/exchange` demonstrates RFC 8693. A service that receives a user's token trades it for one of its
own rather than passing the original onwards — which would hand every downstream hop everything the
user ever granted.

The user's access token carries **`may_act`** (RFC 8693 §4.4): a statement by the authorization
server naming who is allowed to become the actor for this subject. Everything the page does follows
from it:

| | Result |
|---|---|
| **Impersonation** — no actor token | `400 invalid_grant`. Not because the caller was wrong — it was the named one — but because it brought no actor token at all. |
| **Delegation by the service the token names** | `200`, and the token carries `act: {iss, sub: pkce-exchange-client}`. |
| **Delegation by another service** | `400 invalid_grant`. Its own registration holds the token exchange grant; what it lacks is this user's token naming it. |
| **Asking for more than it may have** | `400 invalid_scope`. A service cannot exchange its way into privileges its own registration does not allow. |

**`may_act` does not merely restrict impersonation — it abolishes it.** A subject token that names
who may act cannot be exchanged by somebody acting anonymously, so the only way through is delegation,
and delegation leaves an `act` claim behind for an audit log downstream to read. That is the whole
argument for setting it: impersonation is exactly the case where nothing downstream can tell the
service from the user.

`sub` never changes — the exchange does not change who the call is *for*. What changes is the
audience and the scope, so a leak at the downstream service costs less than a leak of the original
token.

Two things worth knowing:

* **`may_act.iss` must be a `java.net.URL`, not a `String`.** Spring Authorization Server compares
  `may_act` against the actor token claim by claim with `Objects.equals`, and an issued token's `iss`
  claim is a `URL` by the time it is stored, because `JwtClaimsSet` converts it. A string refuses
  every exchange with `invalid_grant` — indistinguishable from naming the wrong party. Found by
  watching the delegation case fail when it should not have.
* **Authority to exchange is not authority to act for a person.** `pkce-relay-client` exists to make
  that concrete: same grants, same registration quality, refused all the same.

The grant is given only to those two services. The browser-facing clients do not have it: exchanging
is what a downstream service does with a token it received, not something a front end needs.

## Rich authorization requests

`/rar` demonstrates RFC 9396. A scope is one word standing in for whatever the client wants; RAR
replaces it with a structured description of the actual request:

```json
[{"type": "payment_initiation",
  "actions": ["initiate"],
  "locations": ["https://api.example.com/payments"],
  "instructedAmount": {"currency": "EUR", "amount": "123.50"},
  "creditorName": "Merchant A"}]
```

The consent screen then says *"Initiate a payment of 123.50 EUR to Merchant A"* rather than offering
a `payments` scope, and the issued token carries the same structure — so a resource server knows the
amount and the creditor that were approved instead of taking the client's word for them.

**Spring Authorization Server has no RFC 9396 support at all** — no parameter, no classes — so this
is built on its extension points:

* An `AuthenticationConverter` on the **pushed request endpoint** rejects types the server does not
  implement, answering `invalid_authorization_details` as section 5 specifies. It has to be there
  rather than on the authorization endpoint: with PAR the details travel in the push, and the later
  redirect carries only a `request_uri`.
* The **consent controller** looks the pending authorization up by `state` to find what was actually
  requested, since the consent redirect carries only the state.
* A **token customizer** copies the approved details into the issued token.

`authorization_details` survives into the stored authorization for free — Spring Authorization Server
keeps unrecognised authorization request parameters in `additionalParameters`, which is what makes
this practical at all.

Not implemented: echoing `authorization_details` in the token *response* body, which the RFC also
calls for. The claim in the token covers the demonstration.

What happens when a resource server actually holds an operation against that grant is
[its own page](#enforcing-authorization_details).

## Backchannel authentication (CIBA)

`/ciba` demonstrates OpenID Connect CIBA. The client names the user it wants to authenticate and
waits; the user approves on a device of their own. There is no redirect, no browser, and the user
never visits the client — which is what makes it work for a call centre agent asking you to confirm
something, or a payment terminal.

1. The client posts `scope`, `login_hint` and a `binding_message` to `/backchannel/authenticate` with
   its own credentials, and gets back `auth_req_id`, `expires_in` and `interval`.
2. The user sees the request on their own device — a push notification in practice — and approves or
   refuses it.
3. The client polls `/oauth2/token` with `grant_type=urn:openid:params:grant-type:ciba`. Until the
   user acts that is `authorization_pending`, then either a token or `access_denied`.

**Against the device flow**, which also polls and also moves approval elsewhere: there, the *user*
carries a code from the device to their browser and the device has no idea who they are. In CIBA the
*client* says who it wants up front and the user is found for it. So CIBA only works where the client
already knows the user, and the `binding_message` — shown on both sides — is what stops someone
approving a request they did not trigger.

**Spring Authorization Server has no CIBA support**, so:

* the backchannel endpoint is a plain controller, including the client authentication the framework
  would otherwise have done;
* the grant is taught to the token endpoint with an `AuthenticationConverter` and an
  `AuthenticationProvider`;
* pending requests live in their own `ciba_request` table rather than being forced into
  `oauth2_authorization`.

An approval is single-use: collecting the token marks it consumed, and polling again is
`invalid_grant`. Only the user the request names can answer it.

Two things the demo does that a deployment would not: the approval page is reached by a link rather
than a push notification, and running the client and the "phone" in one browser means they share a
session, which is why the polling endpoint is exempt from CSRF.

## Step-up authentication (acr / amr)

`/stepup` demonstrates authentication levels. A token does not only say *who* the user is — `acr`
says how strongly they authenticated and `amr` says by what means, so a resource server can insist on
a level rather than accepting any valid token for everything.

| | `acr` | `amr` |
|---|---|---|
| Password only | `urn:demo:loa:1` | `[pwd]` |
| After the step-up | `urn:demo:loa:2` | `[pwd, otp]` |

A client asks with `acr_values`. If the session falls short, the authorization endpoint saves the
request, collects the missing factor, and resumes — so the token is only ever issued once the level
is genuinely met. An existing token is never upgraded in place: raising the level means getting a new
one.

The levels come from Spring Security 7's `FactorGrantedAuthority`, which records each factor and when
it was satisfied. The form login contributes `FACTOR_PASSWORD`; the step-up *adds*
`FACTOR_OTT` rather than replacing the authentication, which is what makes `amr` list both.

Three things worth knowing:

* **`acr_values` is ignored by Spring Authorization Server**, so a filter on the authorization
  endpoint enforces it. Without it a client could ask for a stronger authentication and be handed a
  token that quietly says otherwise.
* **The demo uses the public client, not the PAR one.** A pushed request leaves only a `request_uri`
  in the browser, so `acr_values` would never reach the endpoint that enforces it — enforcing it for
  pushed requests means checking at the push, where there is no user session yet.
* **The one-time code is shown on screen**, because the demo has nowhere to send it. That is the one
  part that is not faithful: a real second factor lives on a device the user already holds.

The client here decides in advance that it wants a stronger authentication. For the case where it
does not know until it is refused, see [the step-up challenge](#step-up-challenge-rfc-9470); for the
other axis — how *recently* rather than how strongly — see
[authentication freshness](#authentication-freshness-max_age--auth_time).

## Step-up challenge (RFC 9470)

`/stepup-challenge` is the other half of the page above, and the half that happens in practice. There
the client decides in advance that it wants a stronger authentication; here it has no idea, calls the
operation with the token it holds, and the **resource server** tells it what is missing.

`/resource/transfer` has its own resource server chain: an ordinary bearer token, then a look at the
`acr` claim on it.

| Called with | Result |
|---|---|
| A token carrying `urn:demo:loa:1` | `401` + `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="urn:demo:loa:2", max_age="300"` |
| The same call after re-authorizing | `200`, and the body echoes `acr: urn:demo:loa:2`, `amr: [pwd, otp]` |

In between, the client does the only thing the challenge leaves it: starts a new authorization
request carrying the `acr_values` it was handed — read off the header, not chosen by the page — which
runs into the enforcement filter from the section above and collects the second factor.

Notes:

* **Spring Security writes no such challenge.** The string `insufficient_user_authentication` appears
  in no Spring Security 7.1.1 module. `BearerTokenAccessDeniedHandler` answers `403` with
  `insufficient_scope` (RFC 6750 §3.1), which is right for a missing scope and wrong here: a scope is
  granted once and the user cannot fix it by trying harder, while an authentication level can be
  raised by asking for one more factor. The status carries that difference — `401` says authenticate
  again, `403` says do not bother. `InsufficientUserAuthenticationHandler` exists because nothing
  shipped does this; a test pins both behaviours side by side.
* **The challenge is the only way the client could know.** Without it a refusal is a dead end:
  retrying is pointless and re-authorizing blindly means guessing which of the server's levels was
  meant. RFC 9470 §3 defines exactly `acr_values` and `max_age` for that reason.
* **The client's record of the challenge cannot live in the session.** Acting on it starts a new
  authorization request, and `RestartOAuth2LoginFilter` invalidates the session when it does — so the
  run is kept per user in the service instead. That is not a workaround: a challenge is the client's
  own state, and a real client would not keep it where the authorization server's login could discard
  it either.
* **`max_age` is sent and not enforced.** RFC 9470 lets a resource server say how fresh it wants the
  authentication to be, and the challenge carries it. Spring Authorization Server has no `max_age`
  handling at all — the parameter appears nowhere in its sources — so passing it on would change
  nothing, and the page does not pretend the round trip refreshes anything but the `acr`.

## Authentication freshness (`max_age` / `auth_time`)

`/freshness` is the other question OpenID Connect Core §3.1.2.1 lets a client ask.
[`acr_values`](#step-up-authentication-acr--amr) asks *how strongly* the user authenticated;
`max_age` asks *how recently*, and the answer comes back as `auth_time`. A session an hour old is
still a valid session — it is just not evidence that the person at the keyboard is the one who signed
in.

The page shows your own session's `auth_time` and what each `max_age` would mean for it, then runs a
probe that asks the authorization endpoint the same question three ways:

| Asked | Re-authenticated | `auth_time` |
|---|---|---|
| `max_age=3600` | no | unchanged — a session seconds old is inside an hour's grace |
| `max_age=0` | **yes** | moved forward, and the new token says so |
| `prompt=login` | no | unchanged — nothing acted on it |

The probe signs in a **separate** session on purpose. Client and authorization server share one
session in this demo, so a second authorization request from the page's own session restarts the
login whatever it carries (`RestartOAuth2LoginFilter`), and all three rows would look identical.

Notes:

* **Spring Authorization Server does not know the word `max_age`.** The string appears nowhere in
  it, so `MaxAgeRequiredFilter` enforces the parameter, sitting beside the filter that enforces
  `acr_values` — two halves of one specification paragraph, neither implemented by the server.
  Spring's OAuth2 **client** has no `max_age` either, so a browser client here passes it the way it
  already passes `acr_values`, through the demo's own request resolver.
* **`prompt=login` is validated and then ignored.** `OidcPrompt` lists `none`, `login`, `consent` and
  `select_account`, and a request combining `none` with any of the others is refused — but `none` is
  the only value ever acted on, answered with `login_required` or `consent_required`. The value that
  means *do not interrupt the user* is implemented; both values that ask the server to *start* an
  interaction are not.
* **`max_age=0` needs a guard against itself.** The login it forces is moments old, so the resumed
  request is judged stale again and the browser bounces for ever. The filter marks the one request it
  has already sent back — by its `state`, in the session it deliberately kept — and lets that request
  through when it returns. Read strictly, zero has the opposite problem: an authentication that just
  happened has an elapsed time of zero at any resolution, and zero is not *greater than* zero, so the
  parameter would ask for nothing at all. Everyone reads it as "prove it again now", and so does
  this; a test pins both halves.
* **The filter takes the authentication away without touching the session.** The client's own
  authorization request — its state and PKCE verifier — lives in that session, and invalidating it
  would strand the callback with `authorization_request_not_found`.
* **`auth_time` is the *latest* factor, not the first.** `JwtGenerator.getAuthenticationTime` takes
  the most recent `FactorGrantedAuthority`, so a step-up moves it forward — and a forced login leaves
  one factor behind, dropping `acr` back to `urn:demo:loa:1` while `auth_time` moves up. Recent and
  strong are genuinely different axes.
* **A pushed request would slip past it**, for the same reason `acr_values` does: enforcement reads
  the query string, and [PAR](#pushed-authorization-requests) leaves only a `request_uri` there.
* **A silent request cannot be prompted at all**, so the filter stands down for it — see
  [silent authentication](#silent-authentication-promptnone).

## Silent authentication (`prompt=none`)

`/silent-auth` demonstrates the request behind every silent renewal in a hidden iframe. OpenID
Connect Core §3.1.2.1: `prompt=none` asks *is there still a session, and may I have a token for it?*
and forbids the authorization server from showing the user anything at all. If it cannot answer
alone, it says so in an error the client can read.

The probe takes one client through the whole life of the parameter. Nothing is followed — where the
first response points **is** the answer:

| Asked | Answer |
|---|---|
| `prompt=none`, before there is a session | `login_required` |
| `prompt=none`, signed in, never agreed | `consent_required` |
| `prompt=none`, signed in, agreed once already | an authorization code, silently |
| `prompt=none login` | `invalid_request` |
| `prompt=none&max_age=0` | `login_required` |

Notes:

* **Spring Authorization Server implements this one.** Unlike [`acr_values`](#step-up-authentication-acr--amr)
  and [`max_age`](#authentication-freshness-max_age--auth_time), which it does not read at all,
  `prompt` is parsed, validated and acted on. Of the four values `OidcPrompt` names, though, only
  `none` does anything — the ones that ask the server to *start* an interaction are accepted and
  ignored.
* **The `login_required` it implements could never run here.** Its endpoints sit behind
  `anyRequest().authenticated()` with a login entry point — the arrangement in its own sample, and in
  this demo — so an unauthenticated request is redirected to the login page several filters before
  the authorization server sees it. That is exactly what `prompt=none` forbids: a question asked in a
  hidden iframe, answered with a login form nobody will ever look at. `PromptNoneFilter` answers
  those requests itself and leaves every other case to the server.
* **The last row is two of this demo's own rules colliding.** `max_age=0` says the session must be
  newly authenticated; `prompt=none` says the user may not be asked. Both cannot hold, so the answer
  is `login_required` — and `MaxAgeRequiredFilter` has to stand down rather than redirect to the
  login page it would otherwise use. A parameter that enforces something must know about the
  parameter that forbids the enforcement.
* **An error may only be sent where the client registered it.** The filter looks the client up and
  checks the `redirect_uri` against the registration before writing anything to it — the same rule
  the authorization server applies. Without that check, an error response is an open redirect; a
  test pins it.
* **Two of the specification's four errors never appear.** `interaction_required` and
  `account_selection_required` are not in Spring Authorization Server at all.
* **The run forgets the stored consent first.** A consent, once given, is remembered, so a second run
  would find the user had already agreed and the middle row would answer itself.

## `request_uri` expiry and one-time use

`/request-uri` is about the reference itself. [Pushing an authorization request](#pushed-authorization-requests)
replaces a long query string with a short one, and as far as the browser is concerned that reference
*is* the authorization request — so how long one lasts and how often it works decides what a leaked
URL is worth.

The probe pushes one request and spends it five ways:

| Spent | Answer | Still stored |
|---|---|---|
| Once, by the client that pushed it | a code | no |
| The same reference a second time | `invalid_request` | no |
| One whose expiry has passed | `invalid_request` | no |
| The same reference with a later expiry written into it | `invalid_request` | no |
| Presented by a different client | `invalid_request` | **yes** |

Notes:

* **One-time use is a deletion, not a flag.** Spring Authorization Server removes the stored request
  the moment it is consumed — at the consent screen as well as at the redirect — so the second
  attempt is not refused for having been used before. It is refused because there is nothing there.
* **The expiry is enforced by deleting it too.** An expired reference is removed before the error is
  returned, so the first retry is what clears the row.
* **Editing the expiry cannot help.** The value the request is stored under is the random part *and*
  the expiry, joined by `___`. Move the number a year out and the reference names nothing: the lookup
  fails before the expiry is ever compared. Plain sight and tamper-evident at once, with no signature
  anywhere.
* **Five minutes, and nothing to configure.** `OAuth2PushedAuthorizationRequestUri.create()`
  hard-codes `Instant.now().plusSeconds(300)`; there is no setting for it on the client or the
  server. A deployment wanting a different lifetime would have to replace the provider.
* **A refusal that cannot reach the client lands on the user.** Every failure above is answered with
  `400` and an error page rather than `error=invalid_request` at the redirect URI — the only record
  of where to send that was the pushed request the server just deleted or never had.
* **The reference is not a secret, and does not need to be.** The last row presents a perfectly valid
  one as a different client and gets nowhere, and the reference survives: a failed lookup consumes
  nothing.
* **The expiry was moved, not waited out.** The third row rewrites the stored request so it is keyed
  by an expiry a minute in the past. What is faked is the clock, not the check.

## Enforcing `authorization_details`

`/rar-enforcement` is the other half of [rich authorization requests](#rich-authorization-requests).
There a user approves a particular payment rather than a category, and the token comes back carrying
what they agreed to. That is worth something only if somebody checks it.

`/payments` is a resource server that reads `authorization_details` off the token and holds the
instruction against it. The probe gets two tokens for the same user — one carrying the granted detail
below, one carrying none — and instructs five payments:

```json
{"type":"payment_initiation","actions":["initiate"],
 "instructedAmount":{"currency":"EUR","amount":"25.00"},
 "creditorName":"Merchant Ltd","creditorAccount":{"iban":"DE02100100109307118603"}}
```

| Instructed | With | Answer |
|---|---|---|
| 25.00 EUR to the approved account | the approved token | `200` |
| 500.00 EUR to the approved account | the approved token | `403` — the grant covers 25.00 |
| 25.00 EUR to a different account | the approved token | `403` — a different creditor |
| 25.00 EUR to the approved account | a token with no `authorization_details` | `403` — nothing was approved |
| 25.00 EUR to the approved account, again | the approved token | `200` |

Notes:

* **A grant is not a voucher.** The last row is the first row again, and it is accepted again. RFC
  9396 describes what was *authorized*, not how many times it may happen, and nothing in the token
  could record that it had been spent. A resource server that means "one payment" has to keep that
  count itself.
* **There is no error code for this.** RFC 9396 registers none, so the refusal uses RFC 6750 §3.1's
  `insufficient_scope` with a description naming what exceeded the grant. It is the closest thing
  that exists and it is not quite right — the scope was never the problem. Compare
  [the step-up challenge](#step-up-challenge-rfc-9470), where RFC 9470 did define an error the client
  can act on.
* **The check cannot live in a filter.** Whether the token permits the operation depends on the
  amount and the account in the request body, which no `SecurityFilterChain` rule can see. The chain
  answers only "is this token valid"; the endpoint does the rest, which is where RFC 9396 leaves it.
* **An ordinary token is refused, not waved through.** The fourth row carries a valid token for the
  same user and the same scopes and asks for the payment that *was* approved on the other token. It
  fails because a missing `authorization_details` is treated as nothing granted rather than as
  nothing to check — the opposite reading is the mistake this page exists to name.
* **Spring Authorization Server contributes the carriage, not the meaning.** It has no RFC 9396
  support: the demo's validator refuses unknown types at the pushed request endpoint, a token
  customizer copies the approved array onto the token, and the resource server reads that claim back.
  Nothing in the server knows an amount from an account number.

## DPoP nonces

`/dpop-nonce` closes a gap the [DPoP page](#sender-constrained-tokens-dpop) leaves open. A proof says
the caller holds a key; it does not say *when* they held it. Every value in one is chosen by the
client — the identifier, the timestamp, the method, the URI — so a proof can be made in advance and
kept, and one that leaks into a log is usable until it ages out. RFC 9449 §9 closes that window: the
resource server hands out a **nonce** and insists the next proof echo it back.

`/nonce/me` is a DPoP-only resource that demands one. The probe gets a bound token and calls it five
times:

| Proof carried | Answer | Came back with |
|---|---|---|
| no nonce claim | `use_dpop_nonce` | `DPoP-Nonce: A` |
| nonce A | `200` | `DPoP-Nonce: B` |
| nonce A again | `use_dpop_nonce` | `DPoP-Nonce: C` |
| a nonce nobody issued | `use_dpop_nonce` | `DPoP-Nonce: D` |
| nonce B | `200` | `DPoP-Nonce: E` |

The second row is the loop closing — refused, handed a nonce, new proof, accepted — and the fifth is
why it only has to close once: every answer carries a nonce for next time, the accepted ones
included.

Notes:

* **Neither half exists in Spring Security.** `use_dpop_nonce` and `DPoP-Nonce` appear nowhere in its
  resource server, and Spring Authorization Server's proof verifier never looks at a `nonce` claim —
  it checks the signature, the method, the URI, the token hash, the identifier and the age, and stops
  there. The challenge, the store and the check are this demo's.
* **What a nonce buys** is the one value the client cannot predict, which turns "this caller has the
  key" into "this caller had the key just now".
* **Single use is this server's choice, not the specification's.** RFC 9449 leaves lifetime and reuse
  policy to whoever issues the nonce; one good until it expires is equally conformant. Spending each
  one makes the third row say something.
* **The nonce is read before the proof is verified, deliberately.** The filter parses the claim
  without checking the signature, because all it decides is whether to ask for a nonce — anything
  that gets past it still has to satisfy Spring's own verification. Verifying first would tell a
  client that has never been given a nonce that its proof is bad, which is true of nothing.
* **The authorization server can ask for one too** (RFC 9449 §8, `400` from the token endpoint). This
  page does the resource server half, because that is where a proof is presented over and over.
* **The [DPoP page](#sender-constrained-tokens-dpop) is left alone** — its resource server accepts a
  proof on its own, which is the ordinary arrangement and the one worth seeing first.

## Signed introspection responses (RFC 9701)

`/introspection-jwt` asks what [introspection](#introspection-and-revocation) is worth as evidence. An
RFC 7662 response is a bare JSON object: true of nothing in particular, addressed to nobody, signed by
no one. A resource server that wants to cache that answer, hand it on, or prove later what the
authorization server said needs more — so RFC 9701 lets the same response come back as a signed JWT.

One access token, asked about four ways:

| Asked | Came back as | Signature | Addressed to |
|---|---|---|---|
| `Accept: application/json` | `application/json` | none | nobody — `active: true` |
| `Accept: application/token-introspection+jwt` | the JWT form | verifies | `pkce-exchange-client` |
| the same token, by another client | the JWT form | verifies | `pkce-relay-client` |
| a token that was never issued | the JWT form | verifies | `pkce-exchange-client` — `active: false` |

Notes:

* **Spring Authorization Server has no RFC 9701 support.** Neither the media type nor the
  `token_introspection` claim appears anywhere in it, and the endpoint writes JSON unconditionally.
  What it does give is the hook — `introspectionResponseHandler` on the endpoint configurer.
* **Nothing changes for a client that does not ask.** The handler reads `Accept` and otherwise
  delegates to the same `OAuth2TokenIntrospectionHttpMessageConverter` the server would have used, so
  the introspection page and every existing caller get byte-for-byte what they always did.
* **The audience is the point, not the signature.** A signature says the authorization server wrote
  it; `aud` says who it wrote it *for*. Rows two and three are the same question about the same token
  and the answers are not interchangeable.
* **The `typ` header is not decoration, and the demo proves it by accident.** RFC 9701 types the JWT
  `token-introspection+jwt` so nothing checking only a signature can mistake it for an access token —
  and this server's own `JwtDecoder` bean *refuses* these responses, because Spring Security's
  default validator chain insists on `typ: JWT`. Verifying them needs a second decoder that expects
  the right type; a laxer first one would have been the wrong fix. A test pins the refusal.
* **Two conversions are load-bearing.** The introspection claims hold `Instant`s and collections;
  RFC 7662 wants numeric dates and one space-delimited `scope` string. Handing the Java types to the
  signer fails outright — its serialiser cannot see inside `java.time`.
* **Encryption is the half this does not do.** RFC 9701 also allows the response to be encrypted to
  the client, which matters because it carries scopes and a subject. Signing is the useful half here,
  where the transport is already private and the point is provenance.

## JWT-secured authorization responses (JARM)

`/jarm` is [JAR](#jwt-secured-authorization-requests-jar) pointed the other way. JAR signs the
question so the server knows it arrived as written; JARM signs the answer so the client knows the
same. An ordinary authorization response is a handful of loose query parameters — nothing says who
sent them, nothing says who they are for, and anything that can reach the redirect URI can change
them.

The same authorization is asked for five ways:

| Asked | `response_mode` | Signature | What came back |
|---|---|---|---|
| The ordinary response | `query` | none | `code`, `state`, `iss`, `session_state` |
| Asked for a signed response | `jwt` | verifies | one `response` parameter |
| A refusal, signed the same way | `jwt` | verifies | `error: invalid_scope`, inside the JWT |
| The signed answer, with the code changed | `jwt` | **fails** | — |
| Delivered after the hash | `fragment.jwt` | verifies | `#response=…` |
| Delivered in a form the browser posts | `form_post.jwt` | verifies | a self-submitting page; the client read it from its own request body |
| Asked for a mode nothing here implements | `fragment` | none | `code`, `state`, `iss` |

Notes:

* **Spring Authorization Server does not read `response_mode` at all.** The string appears nowhere
  in it. It implements the authorization code flow, where the answer always goes on the query
  string, so it has never needed the parameter — and a client asking for a signed response gets loose
  parameters with no indication that it asked for anything. The last row is that happening.
* **What the signature protects** is three claims the loose form has no room for: `iss`, so a client
  with several authorization servers knows which one answered — the problem
  [the mix-up page](#mix-up-attack-defence-iss) solves with a bare parameter anything could have
  written; `aud`, so a response delivered to the wrong client means nothing; and `exp`, so a captured
  answer stops being usable. The `code` is protected as a side effect of all three.
* **The failure is signed too.** A client that cannot trust an error is no better off than one that
  cannot trust a code: an attacker who can rewrite `error=access_denied` into `code=…` has done the
  same damage either way.
* **Tampering fails on the signature, not the contents.** The fourth row is the second row's answer
  with one claim rewritten — right issuer, right audience, plausible code, and refused.
* **Which algorithm signs it is the client's choice**, recorded on the registration as
  `authorization_signed_response_alg` — [its own page](#authorization_signed_response_alg).
* **Three deliveries, one JWT.** The signed response is identical in every mode; what differs is
  where it travels. `query.jwt` (and plain `jwt`, the same thing for this flow) puts it on the query
  string, where it reaches the client's server in the request line and therefore its access log.
  `fragment.jwt` puts it after the `#`, which a browser never sends to that server at all.
  `form_post.jwt` puts it in no URL whatsoever — the authorization server answers with a page that
  submits itself, and the client reads its own request body. Length is the practical reason for the
  last one: a signed response is roughly a kilobyte, and URLs have limits that vary by browser and by
  every proxy in between.
* **The form post arrives without a CSRF token**, because it is submitted by a page the authorization
  server wrote — which is the shape of any response arriving from a server elsewhere. `/jarm/callback`
  is exempted for that reason, and it is the one endpoint here that reads a JARM response out of a
  body rather than a URL.

## `authorization_signed_response_alg`

`/jarm-alg` is about the one setting that decides how a
[JARM response](#jwt-secured-authorization-responses-jarm) is signed. The algorithm is the client's
choice, not the server's, and it lives on the registration — three clients here differ in it and in
nothing else.

| Client | Registered as | `alg` in the header | Signed with |
|---|---|---|---|
| `pkce-jarm-client` | nothing | `RS256` | the RSA key |
| `pkce-jarm-ec-client` | `ES256` | `ES256` | the EC key |
| `pkce-jarm-none-client` | `none` | no JWT at all | `invalid_request`, in the clear |

Notes:

* **The algorithm belongs to the registration, not the request.** A client cannot ask per
  authorization request, and that is the point: it knows in advance what it will have to verify, so
  an answer signed with anything else is refused before it is read rather than trusted because it
  arrived.
* **Omitting the setting means `RS256`,** which is JARM's default — a default of "no signature" would
  make the mode opt-out by accident.
* **`none` is not a value this can take.** JARM forbids it: a response mode whose purpose is a
  signature cannot be satisfied by an unsigned JWT. Rather than quietly hand that client loose
  parameters — the silent failure [the JARM page](#jwt-secured-authorization-responses-jarm) is about
  — the server answers with an error in the clear, and the page says it is the registration that
  cannot be honoured rather than the request that failed.
* **The server has to have the key.** Supporting `ES256` meant adding a P-256 key beside the RSA one;
  the encoder picks by algorithm and cannot invent a curve. A registration naming an algorithm there
  is no key for is in exactly the same position as `none`. A test pins that the extra key changes
  nothing else: ordinary tokens are still `RS256`.
* **Spring Authorization Server has no setting for this,** because it has no JARM. `ClientSettings`
  carries arbitrary named settings, so the value lives there and the filter reads it — which is how a
  deployment would extend a registration ahead of the library.
* **Hiding the answer is a separate setting**, and the other half of the same registration:
  [`authorization_encrypted_response_alg`](#authorization_encrypted_response_alg).

## `authorization_encrypted_response_alg`

`/jarm-enc` is the other half of the JARM registration. Signing settles who wrote the answer;
[the algorithm page](#authorization_signed_response_alg) is about that. It does nothing at all about
who can *read* it — a signed JWT is base64, not ciphertext. A client that minds registers
`authorization_encrypted_response_alg` as well, and the signed response becomes the payload of a JWE.

| Client | What it was handed | Readable without a key |
|---|---|---|
| `pkce-jarm-client` | 3 parts — a JWS | `code`, `state`, `iss`, `aud` |
| `pkce-jarm-encrypted-client` | 5 parts — a JWE | nothing |

Decrypting with the client's private key reveals the signed response unchanged, and its signature
still verifies against the server's published keys.

Notes:

* **Signed, then encrypted — the order is not a preference.** JARM nests the signed JWT inside the
  JWE, so the signature is over the response the client will actually read. Encrypting first and
  signing the ciphertext would prove only that somebody signed an opaque blob.
* **The key is the client's, which reverses who publishes what.** Everywhere else here the
  authorization server publishes and clients verify; encryption runs the other way, so the client
  publishes at `/jarm-client-jwks.json` and the registration's `jwkSetUrl` points there. A test pins
  that only the public half is published.
* **What it is actually for.** The response travels over TLS either way, so this is not about the
  wire. It is about everywhere a URL goes afterwards: browser history, a `Referer` header, the
  client's own access log, every proxy in between.
* **The method has a default.** The registration names only `alg`, and `enc` comes out
  `A128CBC-HS256` — JARM's default, visible in the JWE header. The header stays readable by design:
  it says which key and which algorithms undo the encryption, and `cty: JWT` (RFC 7519 §5.2) says
  there is another JWT inside.
* **What the key then encrypts with is a separate setting**, and the shapes it produces differ
  measurably: [`authorization_encrypted_response_enc`](#authorization_encrypted_response_enc).
* **A client that asks for this and publishes nothing is refused,** exactly as one asking for a
  signing algorithm the server cannot produce is. There is no key to encrypt to, and answering in the
  clear instead would defeat the setting.
* **The demo's client and server share a process,** so this one key set is read from the bean rather
  than fetched from a port the application would be calling itself on. Every other JWKS URL still goes
  over the network, as a real one always would.

## `authorization_encrypted_response_enc`

A JWE is encrypted twice over. [`alg`](#authorization_encrypted_response_alg) says how the content
encryption key is wrapped for the recipient; `enc` says what that key then encrypts the payload with.
They are chosen independently, and `/jarm-enc-method` changes only the second — three registrations
identical but for one word, with `alg` fixed at `RSA-OAEP-256` throughout.

| Client | Registered as | `enc` in the header | Shape of the JWE |
|---|---|---|---|
| `pkce-jarm-encrypted-client` | nothing | `A128CBC-HS256` | iv 16 bytes, ciphertext 928, tag 16 — 9 bytes of padding over a 919-character payload |
| `pkce-jarm-gcm-client` | `A256GCM` | `A256GCM` | iv 12 bytes, ciphertext 911, tag 16 — no padding at all |
| `pkce-jarm-unsupported-enc-client` | `A192CBC-HS384` | no JWE at all | `invalid_request` |

Notes:

* **CBC pads and GCM does not.** `A128CBC-HS256` is AES in CBC mode with a separate HMAC, and CBC
  works a block at a time, so the payload is rounded up to a multiple of sixteen bytes whether it
  needs it or not. `A256GCM` is a stream cipher with an authentication tag, and its ciphertext is
  exactly as long as what went in. That is the difference the measurements show, and the only one
  visible from outside.
* **The IV differs too** — sixteen bytes for CBC, one cipher block; twelve for GCM, the size its
  counter construction is defined for. Neither is secret; both travel in the clear as the JWE's
  second-to-last segment.
* **Both are authenticated, by different routes.** CBC gets its integrity from the HMAC named in the
  second half of `A128CBC-HS256`, computed over the ciphertext; GCM produces its tag while
  encrypting. Either way the tag is 16 bytes and a changed byte makes decryption fail.
* **The key lengths are not what they look like.** `A128CBC-HS256` needs a 256-bit content encryption
  key — half for AES-128, half for the HMAC — while `A256GCM` needs 256 bits for AES alone. The
  wrapped key is the same size in both rows regardless, because RSA-OAEP output is fixed by the
  modulus rather than by its contents.
* **An unsupported method is refused, not downgraded.** `A192CBC-HS384` is a real JWA method this
  server does not offer; falling back to one it does would hand the client something other than what
  it registered, without saying so.
* **Nothing about the plaintext changes.** Every encrypted row decrypts to the same three-part signed
  JWT it would have carried unencrypted. `enc` decides the wrapping and nothing else.

## Request object encryption

`/jar-enc` is RFC 9101 §6.2, and the mirror of
[JARM's encryption](#authorization_encrypted_response_alg). A signed request object settles that the
request arrived as the client wrote it; it says nothing about who can read it. The request travels in
the browser's URL carrying whatever the client put there — a `login_hint` is somebody's email
address, [authorization details](#rich-authorization-requests) are an amount and an account number.

The same request, sent three ways:

| Sent | Shape | What the server did | Readable in the URL |
|---|---|---|---|
| Signed, as RFC 9101 requires | a JWS | acted on it | `client_id`, `redirect_uri`, `scope`, `login_hint`, `state` |
| Signed, then encrypted to this server | a JWE | acted on it | nothing |
| Encrypted to a key this server does not hold | a JWE | `The request object could not be decrypted` | nothing |

Notes:

* **Signed then encrypted, and both still checked.** The server decrypts first and then does exactly
  what it did before — type, signature against the client's published key, audience, expiry.
  Encryption says only that nobody else read the request; the signature check is not optional once
  one arrives encrypted, and a test pins that a wrongly signed object inside a correct JWE is still
  refused.
* **The direction is the opposite of JARM's.** There the server encrypts to a key the client
  publishes; here the client encrypts to a key the server publishes. Each party encrypts to whoever
  is going to read it, which is why both sides end up publishing a key set.
* **The server's encryption key is not one of its signing keys.** A third key was added to
  `/oauth2/jwks` marked `use: enc`, leaving the RS256 and ES256 keys alone. A client picks by that
  marking, and the published set still carries no private material.
* **Addressed elsewhere is refused before the signature is looked at,** because until it is decrypted
  there is nothing to look at.
* **The JWE header is checked before the key is used at all.** Which algorithm a client may wrap with
  is [its own registration](#request_object_encryption_alg), read off the header and compared before
  any private key operation happens.
* **[Pushing the request](#pushed-authorization-requests) solves an overlapping problem.** A pushed
  request never travels through the browser, so nothing in it reaches a log on the way; encryption is
  what protects an object that does travel that way. FAPI asks for both.

## `request_object_signing_alg`

`/jar-alg` is RFC 9101 §10.1. A [request object](#jwt-secured-authorization-requests-jar) names its
own algorithm, in its own header, and a server that simply believes it has let the sender choose how
the signature will be checked. `request_object_signing_alg` is the client saying in advance which one
it will use, so the header stops being a choice and becomes a claim that can be wrong.

Two clients share one RSA key. RS256 and PS256 differ in the padding, not in the key, so the same key
signs either — which is what makes the registered algorithm worth registering:

| Sent | Client | Registered | Header said | What the server did |
|---|---|---|---|---|
| Signed with what it registered | `pkce-demo-client` | `RS256` | `RS256` | an authorization code |
| The same key, the other padding | `pkce-demo-client` | `RS256` | `PS256` | `signed with PS256, and this client registered RS256` |
| Signed with what it registered | `pkce-jar-ps-client` | `PS256` | `PS256` | an authorization code |
| The algorithm the other client registered | `pkce-jar-ps-client` | `PS256` | `RS256` | `signed with RS256, and this client registered PS256` |
| Not signed at all | `pkce-demo-client` | `RS256` | `none` | `The request object is not a signed JWT` |

Notes:

* **The second row is a perfectly good signature.** PS256 over the same key, verifying correctly,
  refused anyway. The question is not whether the signature is valid but whether this client agreed
  in advance to sign this way. A server that accepts any algorithm it happens to support has no
  agreement to check against, and an attacker who can influence the header is choosing the
  verification path.
* **It cuts both ways.** The fourth row is the PS256 client sending RS256 — the algorithm the *other*
  client registered, and the one most servers would take without comment. A registration that only
  ever ruled things in would not be a constraint.
* **`none` is a value in the agreement, not the absence of one.** The last row is refused by the same
  comparison as the rows above it rather than by anything special about being unsigned — and a client
  that registers `none` is [a separate matter](#request_object_signing_alg-none). (This bullet
  previously said an unsigned object never reached the algorithm check, which was true of the
  implementation before `none` was supported.)
* **Spring Authorization Server has no setting for this,** and no notion of the `request` parameter
  either. The algorithm travels as a custom client setting,
  `settings.client.request-object-signing-alg`, read by `JwtSecuredAuthorizationRequestFilter` — the
  same arrangement [`authorization_signed_response_alg`](#authorization_signed_response_alg) uses in
  the other direction.
* **Absent is not "anything".** OpenID Connect Discovery treats a missing
  `request_object_signing_alg` as the client not committing; this server treats it as `RS256`, which
  is a narrower reading and a deliberate one. The permissive reading gives back exactly what
  registering the algorithm was meant to take away.

## `request_object_encryption_alg`

`/jar-enc-alg` is the sibling of [`request_object_signing_alg`](#request_object_signing_alg), and the
two registrations do not say the same kind of thing. OpenID Connect Dynamic Client Registration on
the signing one: request objects from this client **"MUST be rejected, if not signed with this
algorithm"**. On the encryption one: the client **"MAY still use other supported encryption
algorithms or send unencrypted Request Objects, even when this parameter is present"**.

So read literally, `request_object_encryption_alg` constrains nothing. This server treats it as a
constraint anyway. Three clients, one server key — every one of these algorithms wraps the same
content encryption key with the same RSA key and differs only in how:

| Sent | Client | Registered | Header said | What the server did |
|---|---|---|---|---|
| Wrapped with what it registered | `pkce-demo-client` | `RSA-OAEP-256` | `RSA-OAEP-256` | an authorization code |
| A stronger hash than it registered | `pkce-demo-client` | `RSA-OAEP-256` | `RSA-OAEP-512` | `encrypted with RSA-OAEP-512, and this client registered RSA-OAEP-256` |
| Wrapped with what it registered | `pkce-jar-oaep512-client` | `RSA-OAEP-512` | `RSA-OAEP-512` | an authorization code |
| The algorithm the other client registered | `pkce-jar-oaep512-client` | `RSA-OAEP-512` | `RSA-OAEP-256` | `encrypted with RSA-OAEP-256, and this client registered RSA-OAEP-512` |
| Exactly what it registered, and retired here | `pkce-jar-rsa15-client` | `RSA1_5` | `RSA1_5` | `This server does not decrypt RSA1_5 request objects` |
| Signed only | `pkce-jar-oaep512-client` | `RSA-OAEP-512` | not encrypted | an authorization code |

Notes:

* **This is stricter than the spec it implements, deliberately.** Rows two and four are both legal
  under the registration text quoted above. A declaration that constrains nothing leaves the choice
  of key-wrapping algorithm with whoever sent the request, which is the party you least want
  choosing it — but it is a departure, and worth knowing is a departure.
* **The unencrypted row is where the spec is followed.** Registering an algorithm says *how* a client
  will encrypt, not *that* it will. A deployment that wants encryption to be mandatory has to say so
  somewhere else; that is what a profile is for.
* **Matching the registration is necessary, not sufficient.** The fifth row sends exactly what its
  client registered and is refused anyway: `RSA1_5` is a real JWA algorithm this server does not
  implement, and one left out of `SUPPORTED_ENCRYPTION_ALGS` was left out on purpose — it is the
  padding Bleichenbacher's attack is about. A registration cannot add an algorithm to a server.
* **The algorithm is checked before anything is unwrapped.** The header is read, compared and
  rejected without a private key operation, which is also the order that keeps a wrong `alg` from
  becoming a decryption attempt.
* **Only the wrapping changes.** Every accepted row decrypts to the same three-part signed JWT, then
  checked exactly as an unencrypted one is — type, signature, audience, expiry.
  [`request_object_encryption_enc`](#request_object_encryption_enc) decides the other half, the way
  [JARM's two settings](#authorization_encrypted_response_enc) divide the same work.

## `request_object_encryption_enc`

`/jar-enc-method` is the other half of the pair.
[`request_object_encryption_alg`](#request_object_encryption_alg) decides how the content encryption
key reaches the server; `enc` decides what that key then does to the request object. They are
registered and chosen separately, and unlike the `alg`, this one has a default the registration spec
writes down itself: *"If `request_object_encryption_alg` is specified, the default
`request_object_encryption_enc` value is `A128CBC-HS256`."*

Four clients, one server key, one request object. Everything below is wrapped with `RSA-OAEP-256`, so
only the content encryption changes:

| Sent | Client | Registered | Header said | Shape | What the server did |
|---|---|---|---|---|---|
| what it registered | `pkce-demo-client` | nothing | `A128CBC-HS256` | iv 16, tag 16, padded | an authorization code |
| a method it never registered | `pkce-demo-client` | nothing | `A256GCM` | iv 12, tag 16, no padding | `encrypted with A256GCM, and this client registered A128CBC-HS256` |
| what it registered | `pkce-jar-gcm-client` | `A256GCM` | `A256GCM` | iv 12, tag 16, no padding | an authorization code |
| the other client's method | `pkce-jar-gcm-client` | `A256GCM` | `A128CBC-HS256` | iv 16, tag 16, padded | `encrypted with A128CBC-HS256, and this client registered A256GCM` |
| exactly what it registered | `pkce-jar-unsupported-enc-client` | `A192CBC-HS384` | `A192CBC-HS384` | iv 16, **tag 24**, padded | `This server does not decrypt A192CBC-HS384 content` |
| a registration the spec forbids | `pkce-jar-enc-only-client` | `A256GCM`, no `alg` | `A256GCM` | iv 12, tag 16, no padding | `registered A256GCM and no algorithm to wrap the key with` |

Notes:

* **The shape column is the only part of this a wire observer could check.** CBC encrypts in blocks
  and pads up to a boundary, with a 16-byte IV; GCM is a stream cipher with a 12-byte nonce and no
  padding, so its ciphertext is exactly as long as the payload. Both carry a 16-byte tag for
  different reasons — CBC's is a truncated HMAC computed after the fact, GCM's falls out of the
  encryption itself. The fifth row shows what that means: its tag is **24 bytes**, because a CBC
  method's tag is half of whichever HMAC it names, and that one names SHA-384.
* **This default is the spec's, not this server's invention.** Unlike
  [`request_object_encryption_alg`](#request_object_encryption_alg), where the default here is a
  deliberate tightening, the registration text states it outright. The first row is a client that
  registered neither half and still has a method, because of that sentence.
* **An unsupported method is refused, not downgraded.** Falling back to something this server does
  offer would hand the client different cryptography from the one it asked for without saying so —
  the failure mode worth avoiding even when the substitute is stronger.
* **A method with no algorithm beside it is refused too.** The registration spec: when
  `request_object_encryption_enc` is included, `request_object_encryption_alg` must be as well. The
  last client is registered the way the spec says it cannot be, and this server treats that as a
  registration it cannot honour rather than quietly filling the algorithm in from the default.
* **Nothing about the plaintext changes.** Every accepted row decrypts to the same three-part signed
  JWT, then checked exactly as an unencrypted one is. `enc` decides the wrapping and nothing else.

## `request_object_signing_alg`: `none`

`/jar-none` is what happens when the registered algorithm is `none` and the request object is a JWT
with an empty signature. Reading the specifications in order is an odd experience:

| Where | What it says |
|---|---|
| RFC 9101 §4 | the claims are "signed or signed and encrypted" |
| RFC 9101 §6.1 | decrypting one yields "a signed Request Object" |
| RFC 9101 §10.5 | defines `require_signed_request_object`, whose job is to refuse `alg: none` |
| OIDC Registration | "The value `none` MAY be used." |

The first two read as though unsigned request objects do not exist; the third is a security
consideration about switching them off, which is only worth writing if they are otherwise on. This
server follows the fourth and implements the third. Six objects, five of them unsigned:

| Sent | Client | Registered | Header said | What the server did |
|---|---|---|---|---|
| unsigned, as it registered | `pkce-jar-none-client` | `none` | `none` | an authorization code |
| signed, by a client that registered `none` | `pkce-jar-none-client` | `none` | `RS256` | `signed with RS256, and this client registered none` |
| unsigned, by a client that registered RS256 | `pkce-demo-client` | `RS256` | `none` | `signed with none, and this client registered RS256` |
| unsigned, with the defence registered | `pkce-jar-none-strict-client` | `none` + `require_signed` | `none` | `This client registered require_signed_request_object` |
| unsigned, encrypted to this server | `pkce-jar-none-client` | `none` | `none` inside a JWE | an authorization code |
| unsigned, naming another client | `pkce-jar-none-client` | `none` | `none` | `names client pkce-demo-client, and the request names pkce-jar-none-client` |

Notes:

* **Accepting `none` is not the same as accepting anything.** The second row is a properly signed
  RS256 object from the client that registered `none`, and it is refused: the registration is an
  agreement about what will arrive, and a better object than the one agreed is still not the one
  agreed. The third row is the same rule pointing the other way.
* **What is left doing the work.** Strip the signature and a request object still buys the two things
  it was reached for beside integrity — the parameters travel as one unit the server reads instead of
  the query string, and [pushing it](#pushed-authorization-requests) keeps it off the browser
  entirely. What it stops buying is any answer to "who wrote this". That is why RFC 9101 §6.3's rule
  — the `client_id` in the request and the one in the object MUST be identical — is the last row, and
  why this round implemented it: with a signature it is a formality, because the object could only
  have come from the client whose key verified it; without one it is the only thing tying the object
  to the client the request names. It applies to signed objects too, and a test pins that.
* **The encrypted row is the one worth staring at.** It is confidential, it is accepted, and it proves
  nothing about who sent it: this server publishes its encryption key, so anyone can produce a JWE
  addressed to it. A JWE around an `alg: none` object looks like security and is not.
* **The defence outranks the algorithm.** The fourth client registered `none` and
  `require_signed_request_object` together, which is a registration that contradicts itself. A
  downgrade defence that could be talked out of it by the thing it defends against would not be one.
  [The server-wide switch](#require_signed_request_object) works the same way and starts `false`,
  so the page has something to show.
* **Both switches are now published.** `request_object_signing_alg_values_supported` and
  `require_signed_request_object` appear in both discovery documents, cited on
  [the metadata page](#authorization-server-metadata-rfc-8414) as RFC 9101 §4 and §10.5. Spring
  Authorization Server advertises neither, having no notion of the `request` parameter at all.

## `require_signed_request_object`

`/jar-required` is RFC 9101 §10.5, whose title is "Downgrade Attack" and whose first sentence is the
whole problem: unless the protocol is locked down to use JAR, *an attacker may simply use an RFC 6749
request instead and bypass all the protection this specification provides.* Signing request objects
buys nothing if the server still answers the same question asked in a query string.

The section defines `require_signed_request_object` as **both** client and server metadata. The
client half is [on the unsigned page](#request_object_signing_alg-none); this one is the server half,
which applies to every client at once. The same four requests are sent twice, with the switch off and
then on:

| Sent | Client | Switch off | Switch on |
|---|---|---|---|
| what the documents said | every client | `require_signed_request_object: false` | `require_signed_request_object: true` |
| an ordinary authorization request | `pkce-demo-client` | an authorization code | `This server requires request objects to be signed` |
| a signed request object | `pkce-demo-client` | an authorization code | an authorization code |
| an unsigned request object | `pkce-jar-none-client` | an authorization code | `This server requires request objects to be signed` |
| an ordinary request, from the strict client | `pkce-jar-none-strict-client` | `This client registered require_signed_request_object` | `This server requires request objects to be signed` |

Notes:

* **The first row is the attack.** An ordinary OAuth 2.0 authorization request — exactly what every
  page here that is not about JAR sends — and while the switch is off it works perfectly. That is
  §10.5's point: a client can sign its request objects beautifully and gain nothing, because nobody
  made it use one. This round implemented that half; the previous one had only the `alg: none` half,
  which is the same hole seen from the other side.
* **Two refusals from one section, in consecutive sentences.** No request object at all, and a request
  object with [`alg: none`](#request_object_signing_alg-none). Both are something arriving with no
  signature and being acted on anyway.
* **A signed request object is accepted under both settings.** The switch removes ways of asking
  rather than adding checks to the one that remains.
* **The last row needs no server switch.** Its client registered `require_signed_request_object` for
  itself. [Client metadata locks one door](#require_signed_request_object-as-client-metadata); server
  metadata locks all of them, and a deployment that can enumerate its clients usually turns the lock
  one at a time.
* **Only a GET is judged.** The consent screen POSTs back to the same endpoint to continue an
  authorization request that was already made and already checked; treating that as a fresh request
  with a missing request object would refuse the user's own approval.
* **The published document tracks the switch.** Both discovery documents are built per request, so
  flipping the value changes what they say immediately rather than at the next restart — which is what
  makes it metadata about this server rather than a note in a README.
* **What the page does is not what a deployment should do.** Moving a server-wide security setting at
  runtime, from a web page, is a demonstration: it is global for every client while the run lasts and
  is put back in a `finally` block. A real deployment sets it in configuration, once.

## `require_signed_request_object` as client metadata

`/jar-client-required` is the other half of RFC 9101 §10.5. The
[server-wide switch](#require_signed_request_object) locks every door at once; this one is
*registered*, so a client can ask for the lock itself at
[registration time](#dynamic-client-registration-rfc-7591) without the operator deciding anything
about anybody else. The page registers two clients through the registration endpoint while you watch
— the server switch stays `false` throughout, so nothing below is the server's doing:

| Sent | Client | Registered | Carried | What the server did |
|---|---|---|---|---|
| an ordinary request | the control client | nothing | no request object | an authorization code |
| an ordinary request | registered client A | `require_signed_request_object` | no request object | `This client registered require_signed_request_object` |
| a signed request object | registered client A | `require_signed_request_object` | signed | the consent screen |
| an unsigned request object | registered client A | `require_signed_request_object` | unsigned | `signed with none, and this client registered RS256` |
| an unsigned request object | registered client B | `require_signed…` + `none` | unsigned | `This client registered require_signed_request_object` |
| a signed request object | registered client B | `require_signed…` + `none` | signed | `signed with RS256, and this client registered none` |

Notes:

* **The same defence, at a different blast radius.** The server switch is a decision about every
  client, including ones registered years ago by people who have left. The client setting is a
  decision about one client, taken by whoever registers it — which is usually how a lock like this
  actually gets turned.
* **The registration endpoint had to be taught this.** Spring Authorization Server's converters have
  a field for every metadata name they know and drop the rest, so `require_signed_request_object`
  arrived at the endpoint and went nowhere. Both are replaced
  (`RequestObjectClientRegistrationConverters`): one keeps the value on the registration, the other
  echoes it back in the response, because RFC 7591 §3.2.1 makes the response the description of the
  client as the server now holds it — and without the echo a caller cannot tell a server that
  understood it from one that ignored it.
* **A client can register two things that cannot both be satisfied.** Client B asked for
  `require_signed_request_object` and [`request_object_signing_alg: none`](#request_object_signing_alg-none).
  Its unsigned objects are refused by the defence and its signed ones for not being the algorithm it
  registered: nothing it sends can work. Neither rule is wrong; the registration is, and a server
  that silently picked one to ignore would be hiding that from whoever has to debug it.
* **The middle refusal is not the defence.** Client A's unsigned object is refused for the algorithm
  it did not register, never reaching the `require_signed_request_object` check. Two rules can refuse
  the same request, and which one spoke is the difference between "sign this" and "sign this
  differently".
* **Two things the registration asked for and did not get.** These clients asked for
  `token_endpoint_auth_method: none` and came back `client_secret_basic` with a generated secret —
  `OidcClientRegistrationRegisteredClientConverter` handles `client_secret_post`, `client_secret_jwt`
  and `private_key_jwt`, and everything else falls to an else branch (checked against the 7.1.1
  sources). They also asked for no scopes, because this server refuses a registration that asks for
  authority beyond the initial access token's. Neither changes what the page is about, and both are
  worth noticing before building on a registration response you did not read.

## `require_pushed_authorization_requests`

`/par-required` is RFC 9126 §6. [Pushing the request](#pushed-authorization-requests) sends the
parameters over an authenticated back channel and hands the browser a reference — worth nothing while
the same client can also put them in a query string. The setting is the client saying it will not:
*"whether the only means of initiating an authorization request the client is allowed to use is
PAR"*. Five requests, with the server-wide value `false` throughout:

| Sent | Client | Carried | Refused by | What the server did |
|---|---|---|---|---|
| an ordinary request | `pkce-confidential-client` | every parameter, in the query string | — | the consent screen |
| an ordinary request | `pkce-par-required-client` | every parameter, in the query string | the client's registration | `This client registered require_pushed_authorization_requests` |
| a pushed request | `pkce-par-required-client` | `client_id` and `request_uri` | — | an authorization code |
| a `request_uri` nobody issued | `pkce-par-required-client` | `client_id` and `request_uri` | the authorization server | `invalid_request` |
| a signed request object instead | `pkce-par-required-client` | `client_id` and a signed `request` | the client's registration | `This client registered require_pushed_authorization_requests` |

Notes:

* **The first two rows are the same request.** Same parameters, same query string, same kind of
  confidential client — one acted on and one not, and the only difference is a boolean on a
  registration. That is the piece [the PAR page](#pushed-authorization-requests) cannot show, because
  a demo that pushes voluntarily proves nothing about a client that would rather not.
* **Two checks, in order, and the page says which spoke.** The registered lock asks only whether a
  `request_uri` is present — a question about how the request was *started*. Whether that reference
  is real, alive and this client's is the authorization server's own check, and the invented-reference
  row is refused by that one. The difference is "push it" versus "push it again".
* **A signed request object is not a pushed one.** The last row carries a perfectly good
  [JAR request object](#jwt-secured-authorization-requests-jar) and is refused anyway. JAR stops the
  request being changed in the browser; PAR stops it going through the browser at all. They compose —
  FAPI asks for both — but neither substitutes for the other.
* **Both halves are in the RFC, and both are implemented.** RFC 9126 defines
  `require_pushed_authorization_requests` twice: §6 as client metadata, which is this page, and §5 as
  server metadata meaning the server "accepts authorization request data only via PAR". The §5 value
  is published in both documents and has [a page of its own](#require_pushed_authorization_requests-as-server-metadata).
  (An earlier version of the FAPI row said RFC 9126 defines no server metadata for this. It does, in
  §5.)
* **Spring Authorization Server has no setting for it either.** It travels as
  `settings.client.require-pushed-authorization-requests`, read by `PushedAuthorizationRequiredFilter`,
  and is carried through [the registration endpoint](#dynamic-client-registration-rfc-7591) beside the
  request object settings so a client can register for it the way §6 describes.

## `require_pushed_authorization_requests` as server metadata

`/par-server-required` is RFC 9126 §5, the other half of
[the per-client lock](#require_pushed_authorization_requests): *"whether the authorization server
accepts authorization request data only via PAR"*, for every client at once. It is also the switch
[FAPI 2.0 §5.3.1](#fapi-20-security-profile) has been asking for since this demo began. The same four
requests, sent twice:

| Sent | Client | Switch off | Switch on |
|---|---|---|---|
| what the documents said | every client | `require_par: false` | `require_par: true` |
| what the profile page said | every client | `FAIL` | `PASS` |
| an ordinary authorization request | `pkce-confidential-client` | the consent screen | `This server accepts authorization request data only via PAR` |
| a pushed request | `pkce-confidential-client` | the consent screen | the consent screen |
| a signed request object | `pkce-confidential-client` | the consent screen | `…only via PAR` |
| an ordinary request, from the locked-down client | `pkce-par-required-client` | `This client registered require_pushed_authorization_requests` | `…only via PAR` |

Notes:

* **This is the row the FAPI page could not pass.** The profile says the server "shall reject
  authorization requests sent without [RFC9126]" — every client, not the willing ones — and until this
  switch existed there was nothing to turn. The profile row is read at both moments and follows it,
  because that check asks the running configuration: it goes green by the configuration changing
  rather than by the check being rewritten.
* **Server metadata outranks the registration, never the other way.** The last row's client had
  already locked its own door, so it is refused in both columns, and while the switch is on the
  refusal is the server's. A client cannot register its way out of a server-wide rule, which is the
  only arrangement that makes one worth having.
* **A signed request object is still not a pushed one.** A valid
  [JAR request object](#jwt-secured-authorization-requests-jar) is refused while the switch is on.
  [The JAR switch](#require_signed_request_object) is the same idea for the other door; a deployment
  that wants both turns both, which is what FAPI asks for.
* **The pushed endpoint is unaffected, and must be.** A switch that also refused requests at
  `/oauth2/par` would leave a client no way in at all. What it refuses is arriving at the
  authorization endpoint any other way.
* **What the page does is not what a deployment should do.** Moving a server-wide security setting at
  runtime, from a web page, is a demonstration: global while the run lasts, and restored in a
  `finally` block. A real deployment sets it in configuration, once.

## `request_uri_parameter_supported`

`/request-uri-metadata` is about a parameter that means two unrelated things. In RFC 9101 §5.2
`request_uri` is a URL the client hosts and the authorization server **fetches**; in
[RFC 9126](#pushed-authorization-requests) it is a reference the server itself handed out. OpenID
Connect Discovery's `request_uri_parameter_supported` is about the first only — and RFC 9126 §5 says a
pushed reference is usable *"regardless of other authorization server metadata such as
`request_uri_parameter_supported`"*. So this server publishes `false` and accepts one anyway.

What the documents now say, against what leaving them out would have claimed:

| Metadata | Published here | Default if omitted |
|---|---|---|
| `request_parameter_supported` | `true` | `false` — the opposite |
| `request_uri_parameter_supported` | `true` | `true` |
| `require_request_uri_registration` | `true` | `false` — the opposite |

And the four ways of pointing at a request object:

| Sent | Parameter | What the server did |
|---|---|---|
| by value | `request` | the consent screen |
| by a URL to fetch | `request_uri` | the consent screen |
| by a pushed reference | `request_uri` | the consent screen |
| by a reference nobody issued | `request_uri` | `invalid_request` |

Notes:

* **Silence is not neutral.** Omitted, these default to `request_parameter_supported: false` and
  `request_uri_parameter_supported: true`, so a server publishing neither claims it does not read
  `request` and does fetch `request_uri`. This server is the other way round on both counts, and
  Spring Authorization Server advertises neither, having no notion of either parameter. Until this
  page they were absent, which is to say wrong.
* **The second and third rows are the same parameter.** One is a URL this server would have to go and
  fetch; the other is a reference it issued minutes earlier. A client reading
  `request_uri_parameter_supported: false` should conclude "do not host request objects for this
  server", not "do not push".
* **Which check speaks depends on the scheme.** A `request_uri` with an `http` or `https` scheme is a
  URL to fetch and is judged by [the registration rules](#require_request_uri_registration);
  everything else is left to the authorization server's lookup of a pushed reference, which is the
  check that owns those. The test is the scheme rather than the shape of a pushed reference, because
  RFC 9126 §4 leaves that format to the server.
* **`require_request_uri_registration` is the one that constrains fetching,** and is published `true`
  — the spec's default is `false`, the permissive reading of a feature that sends the server
  somewhere on a browser parameter's say-so.
* **Only one of these rows costs the server a connection.** RFC 9101 §10.4.1 and §10.4.2 are both
  about that one: a server that fetches a URL on a client's say-so can be aimed at a victim, and the
  reference is unsigned and rewritable in the browser. PAR does the same job with no outbound request
  at all.

## `require_request_uri_registration`

`/request-uri-registration` needed a feature before it could exist: RFC 9101 §5.2 passing a request
object **by reference**, where the client hosts the object and §5.2.3 says the server *must* send a
GET to fetch it. That is an authorization server making an outbound request because an
unauthenticated browser parameter told it to, which §10.4.1 spends a section on — and its first
mitigation, "check that the value of the `request_uri` parameter does not point to an unexpected
location", is exactly what `require_request_uri_registration` turns on. So this round implemented the
fetch, and the setting now has something to govern.

Four URLs, each sent twice. This application hosts all of them — a demo that aimed a server at
somebody else's host to make the point would be making it the wrong way round:

| Sent | URL | Registration required | Requirement off |
|---|---|---|---|
| what the documents said | — | `require_request_uri_registration: true` | `…: false` |
| a URL this client registered | `/hosted/request-object.jwt` | an authorization code | an authorization code |
| a URL **another** client registered | `/hosted/other-client.jwt` | `not registered for this client` | `The request object names client pkce-confidential-client…` |
| a registered URL serving the wrong media type | `/hosted/wrong-type.jwt` | `served text/plain rather than application/oauth-authz-req+jwt` | same |
| a registered URL whose object points at another | `/hosted/recursive.jwt` | `A request object may not carry request or request_uri` | same |

Notes:

* **Only the third row moves.** With the requirement on it is refused before any request leaves the
  server; with it off the server goes and fetches it, and is saved only by a later check noticing the
  object names somebody else. The value of the setting is not that a different object got through —
  it is that the outbound request happened at all. That is why the default here is `true` while
  OpenID Connect Discovery's is `false`.
* **The list is per client.** That URL *is* registered — to another client. A client that could use
  another's registered URL would make registration a formality, and the rewrite attack in RFC 9101
  §10.4.2 works by changing exactly this parameter in the browser.
* **Registration is necessary, not sufficient.** The last two rows are on the client's own list and
  refused under both settings: §10.4.1 clause (b) checks the media type of the *response* (so the
  fetch sends an open `Accept` and judges what arrives), and §4 forbids a request object carrying
  `request` or `request_uri`, which is clause (d)'s recursive GET. The fetch also requires `https`,
  caps the body, times out after two seconds and does not follow redirects.
* **The https rule, and the carve-out that covers this demo.** RFC 9101 §5.2 says a hosted
  `request_uri` MUST be `https`. OpenID Connect Registration §2 states the same rule with a
  qualification — these URLs "MUST use the https scheme *unless the target Request Object is signed in
  a way that is verifiable by the OP*" — and every object fetched here is signed and verified against
  the client's key. Nothing in this demo is served over TLS, so a URL on its own origin is allowed
  through `http` under that clause, and nothing else is, signed or not: the two specs do not agree and
  the narrower one is free.
* **Nothing about verification changes.** What comes back over the GET is checked exactly as an
  object passed by value is: type, algorithm against the registration, signature, audience, expiry,
  client id.

## `request_uris`

`/request-uris` is the list that [the registration requirement](#require_request_uri_registration)
requires membership of — OpenID Connect Registration §2, "array of `request_uri` values that are
pre-registered by the RP for use at the OP". The page registers two clients through
[the registration endpoint](#dynamic-client-registration-rfc-7591) while it runs: one naming a URL,
one naming none.

What the registration did with the list:

| | |
|---|---|
| Sent as `request_uris` | `…/hosted/for-client.jwt?client_id=listed#Xy3pQ2Zr…` |
| Echoed in the response | the same value, as an array of the same length |
| Held against the client | the same URL with the issued client id written in |

And four requests against it:

| Sent | On its list | What the server did |
|---|---|---|
| the URL it registered | yes | the consent screen |
| the same URL, a different fragment | no | `not registered for this client` |
| the same URL with no fragment at all | no | `not registered for this client` |
| anything at all, from the client that registered none | no | `not registered for this client` |

Notes:

* **The list is matched whole.** Rows two and three are the same URL with a different fragment and
  with none. That is not fussiness: the spec puts a content hash in the fragment so a server that
  *caches* the fetched file can tell a stale copy from a fresh one — "if the fragment value used for a
  URI changes, that signals the server that its cached value for that URI with the old fragment value
  is no longer valid". This server does not cache, so the fragment is simply part of the registered
  string; the effect is the same and the reason is smaller.
* **An empty list is a list.** The last client registered no `request_uris` and is pointed at a URL
  this application hosts and would happily serve. Registering nothing is not registering everything.
* **It goes out as an array and comes back as one.** `request_uris` is the only one of these
  registration parameters that is a list, so the converters join it into one setting on the way in
  and split it back on the way out. A caller that sent a list and read back a string would be right
  to wonder what had happened to it.
* **The https rule has a carve-out, and it covers this demo.** RFC 9101 §5.2 requires a fetched
  `request_uri` to be https. OpenID Connect Registration §2 states it as "MUST use the https scheme
  *unless the target Request Object is signed in a way that is verifiable by the OP*" — which every
  object fetched here is. (An earlier version of the page next door called the http exception
  demo-only; under this clause it is within the rule.)
* **Registering a URL is not trusting it.** What comes back is still checked for media type,
  signature, audience, expiry, and for naming the client that asked. The list settles where the
  server is willing to go and nothing about what it finds there.

## `request_object_signing_alg_values_supported`

`/jar-alg-values` is the server's half of a pair. RFC 9101 §4: the client "can inform the
authorization server of the algorithms that it supports" through
[`request_object_signing_alg`](#request_object_signing_alg), and "likewise, the authorization server
can inform the client" through `request_object_signing_alg_values_supported`. Two lists pointing in
opposite directions, and an algorithm has to be on both.

The three lists RFC 9101 §4 names together, as published:

| Metadata | Value |
|---|---|
| `request_object_signing_alg_values_supported` | `[PS256, RS256, none]` |
| `request_object_encryption_alg_values_supported` | `[RSA-OAEP-256, RSA-OAEP-512]` |
| `request_object_encryption_enc_values_supported` | `[A128CBC-HS256, A256GCM]` |

And five request objects measured against them:

| Sent | Client | Registered | Advertised | What the server did |
|---|---|---|---|---|
| RS256 | `pkce-demo-client` | RS256 | on the list | an authorization code |
| PS256 | `pkce-demo-client` | RS256 | on the list | `signed with PS256, and this client registered RS256` |
| PS256 | `pkce-jar-ps-client` | PS256 | on the list | an authorization code |
| `none` | `pkce-jar-none-client` | none | on the list | an authorization code |
| ES256 | `pkce-jar-es-client` | ES256 | **not** on the list | `This server does not check ES256 signatures on request objects` |

Notes:

* **The list is a capability, not a permission.** Row two sends PS256 — on the list — from a client
  that registered RS256, and is refused. Discovery says what the server is able to check; the client's
  own registration says what it agreed to send. Reading the first as the second is an easy mistake,
  because the metadata is the more visible of the two.
* **Neither condition alone is enough.** Row three sends the same PS256 from the client that
  registered it and is acted on. Row five sends ES256 from a client that registered ES256 and
  publishes a key on the right curve — correctly signed, and refused because the server does not
  advertise checking it. Two rows, two directions, one rule.
* **The other two lists were missing.** RFC 9101 §4 names the encryption algorithm and method lists
  alongside the signing one. Both were implemented here — [algorithms](#request_object_encryption_alg)
  and [methods](#request_object_encryption_enc) — and neither was published until this page, leaving a
  client to discover them by being refused, which is what discovery documents exist to prevent.
* **Every value is derived from the constants the filter enforces,** not from a list kept beside them.
  A document that can drift from the code it describes is worse than no document. Spring Authorization
  Server advertises none of the three, having no notion of the `request` parameter at all.

## `request_object_encryption_alg_values_supported`

`/jar-enc-alg-values` is the encryption sibling of
[the signing list](#request_object_signing_alg_values_supported), with one thing the signing side does
not have: the list says which key-management algorithms this server will unwrap with, and says nothing
about **which key to wrap to**. That is in `/oauth2/jwks`, where this server publishes three keys, two
of them RSA. A client needs all three of: a value from the list, the algorithm
[it registered](#request_object_encryption_alg), and the right key.

| Type | Use | |
|---|---|---|
| RSA | `sig` | signs tokens and JARM responses |
| EC | `sig` | signs for clients that registered ES256 |
| RSA | `enc` | the one request objects are wrapped to |

| Sent | Client | Algorithm | Wrapped to | What the server did |
|---|---|---|---|---|
| RSA-OAEP-256 | `pkce-demo-client` | on the list, registered | `enc` | an authorization code |
| the same | `pkce-demo-client` | on the list, registered | **`sig`** | `could not be decrypted with this server's key` |
| RSA-OAEP-512 | `pkce-demo-client` | on the list, **not** registered | `enc` | `encrypted with RSA-OAEP-512, and this client registered RSA-OAEP-256` |
| RSA-OAEP-512 | `pkce-jar-oaep512-client` | on the list, registered | `enc` | an authorization code |
| RSA1_5 | `pkce-jar-rsa15-client` | **not** on the list, registered | `enc` | `This server does not decrypt RSA1_5 request objects` |

Notes:

* **Rows one and two differ only in the key.** Same algorithm, same client, same registration — one
  wrapped to the key marked `enc`, one to an RSA key marked `sig`. The second is refused with "could
  not be decrypted", which is true and unhelpful: the server cannot tell a client that picked the
  wrong key from an attacker that guessed. The algorithm list does not prevent this and is not meant
  to; `use` on the published key is what does.
* **Both RSA keys now say what they are for.** RFC 7517 §4.2 makes `use` optional, and until this page
  only the encryption key carried it — so a client had to identify the encryption key by the *absence*
  of a marking on the others. All three are marked now, which is the difference between selecting a
  key and guessing one.
* **The list is the server's, not the client's.** Rows three and four send the same advertised
  algorithm and differ only in which client registered it — the same pairing as the signing list, one
  specification over.
* **Off the list is off the list.** Row five is a real JWA algorithm, registered by the client sending
  it, refused because the server does not advertise unwrapping it.
* **The other half of the pair is separate.** This list covers the `alg`, how the content encryption
  key travels; [the `enc` list](#request_object_encryption_enc) covers what that key then does, and
  the two are advertised, registered and chosen independently.

## `request_object_encryption_enc_values_supported`

`/jar-enc-method-values` is the last of the three lists RFC 9101 §4 names. It is advertised separately
from [the algorithm list](#request_object_encryption_alg_values_supported), and a client picks one
value from each — so the two together offer **every pair**, while a client's registration names one.
The page sends all four combinations from two differently registered clients, as a grid each:

`pkce-demo-client` — registered neither half:

| alg ↓ / enc → | A128CBC-HS256 | A256GCM |
|---|---|---|
| RSA-OAEP-256 | **accepted** | wrong enc |
| RSA-OAEP-512 | wrong alg | wrong alg |

`pkce-jar-gcm-client` — registered `RSA-OAEP-256` and `A256GCM`:

| alg ↓ / enc → | A128CBC-HS256 | A256GCM |
|---|---|---|
| RSA-OAEP-256 | wrong enc | **accepted** |
| RSA-OAEP-512 | wrong alg | wrong alg |

And one the lists leave out: `A192CBC-HS384`, from the client that registered it —
`This server does not decrypt A192CBC-HS384 content`.

Notes:

* **The grids are the page.** Four advertised pairs, one usable cell each. A client reading discovery
  and choosing freely from both lists has three ways out of four to be wrong, and the wrongness is not
  about cryptography — every cell is a well-formed JWE this server could open.
* **One client registered no method at all.** OIDC Registration §2 defaults the method to
  `A128CBC-HS256` when an *algorithm* is registered — which `pkce-demo-client` did not do either, so
  both halves of its pair come from this server reading silence as the defaults rather than as
  permission. Its accepted cell is the top left, and nothing about that is visible in the lists.
* **The refusals say which half was wrong.** *wrong alg* was refused before the content encryption
  mattered; *wrong enc* got past the algorithm and failed on the method. Two checks in sequence, and a
  client debugging from one `invalid_request_object` would not know which of its two registrations to
  look at.
* **Off the list is a third kind of no.** The last row is registered by the client sending it, so it
  is not a mismatch — it is refused because the method is on neither list.
* **That completes RFC 9101 §4's three lists.** All published, all derived from the constants the
  filter enforces, and all three either absent or wrong a few rounds ago.

## JWT-secured authorization requests (JAR)

`/jar` demonstrates RFC 9101. The authorization request travels as a JWT the client signed, so the
server can tell it arrived exactly as written. The request URL carries only `client_id` and
`request`; everything else is inside the object.

| Sent as | Result |
|---|---|
| A valid request object | Proceeds to sign-in normally |
| The same object, with `scope=admin.everything` appended to the URL | **Ignored.** Consent offers only the signed scopes, and the token is issued for those |
| One character of the signature changed | `invalid_request_object` |
| Signed by a key the server has never seen | `invalid_request_object` |

The second row is the point. RFC 9101 section 6.1 says the server reads the request object and
ignores what came alongside it, so appending to the URL achieves nothing — verified by following the
flow through to the token, which came back scoped `openid profile email` rather than anything the URL
asked for.

JAR and [PAR](#pushed-authorization-requests) solve overlapping problems from different directions:
PAR keeps the request off the front channel entirely, JAR makes it tamper-evident wherever it goes.
They compose.

Two things this needed:

* **A request-parameter wrapper, not just a parser.** Spring Authorization Server decides which
  parameters count by checking them against the raw query string, so overriding the parameter map
  alone left everything from the JWT filtered straight back out — `getQueryString()` has to be
  rebuilt from the object too.
* **Nimbus directly rather than `NimbusJwtDecoder`.** That decoder pins the JWT type to `JWT` and
  applies the check after any customization, so it cannot accept the `oauth-authz-req+jwt` type RFC
  9101 section 10.8 asks for. The type is still required — just checked explicitly.

The client's key is read from this demo's own configuration rather than the client registration's
`jwkSetUrl`, since the client here *is* the authorization server; a deployment would read it off the
registration.

The same idea pointed at the answer instead of the question is
[JARM](#jwt-secured-authorization-responses-jarm). Hiding the question from everything the
URL passes is [request object encryption](#request-object-encryption).

## Authorization server metadata (RFC 8414)

`/metadata` reads back, over HTTP, the two documents this server publishes about itself:

| | |
|---|---|
| RFC 8414 | `/.well-known/oauth-authorization-server` |
| OpenID Connect Discovery | `/.well-known/openid-configuration` |

Different specifications, overlapping content. Here the OpenID document is the superset — it adds
`userinfo_endpoint`, `end_session_endpoint` and the rest of what OpenID Connect defines — and the two
agree on every field they share. That agreement is the part worth enforcing: where both name a field,
a client's behaviour must not depend on which URL it happened to fetch.

Only four fields are actually demanded: `issuer`, `authorization_endpoint`, `token_endpoint` and
`response_types_supported`. Everything past that is a decade of later specifications each registering
what it needed — the device flow, pushed requests, DPoP, certificate binding, rich authorization
details — which is why the document doubles as a summary of what this demo can do.

Every row names the specification that defines it, and that column has a trap in it: anything the page
has no entry for falls back to "RFC 8414 §2", which is right for the fields RFC 8414 defines and wrong
for every extension. A value added to the documents without an entry is therefore not uncited but
*miscited*. Six were — the three
[request object algorithm lists](#request_object_signing_alg_values_supported), the two OpenID Connect
Discovery `request`/`request_uri` switches, `require_request_uri_registration`, and
`check_session_iframe`, which had been wrong since the session management page was built. A test now
asserts that every field citing RFC 8414 §2 is one RFC 8414 actually defines, so the next addition
cannot slip through the same way.

Eight rows carry a link as well as a citation — the request object and `request_uri` family, and both
halves of the PAR requirement:

| Row | Links to |
|---|---|
| `request_parameter_supported` | [the JAR page](#jwt-secured-authorization-requests-jar) |
| `request_object_signing_alg_values_supported` | [`/jar-alg-values`](#request_object_signing_alg_values_supported) |
| `request_object_encryption_alg_values_supported` | [`/jar-enc-alg-values`](#request_object_encryption_alg_values_supported) |
| `request_object_encryption_enc_values_supported` | [`/jar-enc-method-values`](#request_object_encryption_enc_values_supported) |
| `require_signed_request_object` | [`/jar-required`](#require_signed_request_object) |
| `request_uri_parameter_supported` | [`/request-uri-metadata`](#request_uri_parameter_supported) |
| `require_request_uri_registration` | [`/request-uri-registration`](#require_request_uri_registration) |
| `require_pushed_authorization_requests` | [`/par-server-required`](#require_pushed_authorization_requests-as-server-metadata) |

A document says what a server claims; those pages say what it does about the claim. A test walks every
linked path and asserts the page answers, so a cross-link cannot quietly become a dead end — and rows
whose values this demo has no page for carry no link rather than a guess.

Notes:

* **Spring Authorization Server advertises only what it knows about.** The CIBA grant, the
  `authorization_details` types this demo validates, the `iss` parameter it returns and the scopes
  its clients are registered for are all additions this application makes. `ServerMetadataCustomizer`
  applies them to *both* documents from one place, so they cannot drift apart. A server that
  implements something and does not say so is, to a client reading metadata, a server that does not.
* **RFC 8414 §3.3 is one sentence and it matters:** the `issuer` in the document must be identical to
  the issuer identifier the URL was built from, or none of the response may be used. The page shows
  the same document accepted for one client and refused for another on exactly that basis — the
  [`iss` parameter](#mix-up-attack-defence-iss) reasoning, one step earlier.
* **The well-known string goes in different places.** RFC 8414 §3 inserts it *between the host and
  the path*; OpenID Connect Discovery appends it. For `https://example.com/tenant1` that is
  `https://example.com/.well-known/oauth-authorization-server/tenant1` against
  `https://example.com/tenant1/.well-known/openid-configuration`. The rules agree only when the
  issuer has no path, which is why this bites on the day someone deploys a tenant per path.
* RFC 8414 §2 requires the issuer to be an `https` URL. This demo's is not, so a strict client would
  refuse the document before reading a field of it — the same gap the [FAPI page](#fapi-20-security-profile)
  reports.
* Metadata is a promise, not proof. Nothing in it is signed; the transport and the issuer check do
  the work the document cannot.

## Dynamic client registration (RFC 7591)

`/dynamic-registration` registers a client at runtime. Every other client in this demo was written
into configuration by hand; this one arrives as a JSON document and is handed back a `client_id`, a
secret, and a token for managing its own registration.

The page makes six requests. One works:

| Request | Result |
|---|---|
| With no access token | `401`, with a `WWW-Authenticate` challenge naming where to learn how to authenticate |
| With a token carrying `client.create` **and** `client.read` | `401 invalid_token` |
| Asking for `scope` in the registration | `400 invalid_scope` |
| A well-formed registration | `201`, credentials issued |
| The same initial access token again | `401 invalid_token` |
| Reading the registration back (RFC 7592) | `200` |

Notes:

* **Spring Authorization Server implements OpenID Connect Registration**, which is RFC 7591 with
  OpenID's additions, at `/connect/register`. It is off by default; switching it on is the whole
  configuration, and it brings the `client.create` scope check and the registration access token
  with it. Both metadata documents gain a `registration_endpoint` as a result — before, neither
  mentioned one.
* **A token with too much scope is refused, not narrowed.** The endpoint wants exactly
  `client.create`, so a token that also carries `client.read` fails as `invalid_token`. That is why
  the registrar here asks for one scope at a time.
* **An initial access token is spent by the registration it authorises.** RFC 7591 §3 leaves the
  endpoint's protection to the server; this one burns the token on first use.
* **The `scope` field is refused outright.** RFC 7591 §2 defines it, and this server rejects any
  registration that sets it — a client that could name its own scopes would be granting itself
  authority. A deliberate deviation from the specification, on by default, and it means a newly
  registered client has no scopes at all until something out of band gives it some.
* **The server decides the security posture.** The registration asked for neither PKCE nor consent
  and got both, read back from the stored registration rather than from the response. Registration
  hands out an identity, not authority.
* Anything registered lands in the same table the hand-written clients live in, and RFC 7592's
  delete operation is not implemented here — the only way back is the database.

## Mix-up attack defence (`iss`)

`/mixup` demonstrates RFC 9207 by running the attack it prevents, end to end, against this
application.

A client that supports several authorization servers gets an authorization code at its redirect URI
with nothing in the response saying who sent it. It falls back on its own note — *I started this at
server A* — and an authorization server that the user chose, but that happens to be hostile, can
make that note wrong: it authenticates nobody and forwards the request to the honest server under the
honest client's identity, keeping the client's state, redirect URI and code challenge. What comes
back looks exactly like the answer the client is waiting for.

| | Client ignores `iss` | Client checks `iss` |
|---|---|---|
| Where the token request went | the attacker's token endpoint | nowhere |
| What the attacker received | the code **and** the PKCE code verifier | nothing |
| Outcome | an access token for the user at the honest server | the mismatch caught, the flow abandoned |

**PKCE does not help here.** It protects a code that was intercepted; this code was delivered. The
client sends the code verifier to the token endpoint it believes in, so the attacker gets both halves
at once. Neither does `state` — the attacker forwards the client's own value, so it comes back
matching.

Notes:

* **Neither half of RFC 9207 exists in Spring.** Spring Authorization Server's response handlers send
  `code` and `state` and stop, so `IssuerIdentifierResponseHandler` replaces both the success and the
  error handler and adds `iss`. On the client side `OAuth2AuthorizationResponse` has no field for it
  at all, so the checking client on this page reads the parameter itself.
* The server publishes `authorization_response_iss_parameter_supported` in its discovery document,
  which is how a client learns it may insist on the parameter.
* An error response is an authorization response too, and carries `iss` for the same reason.
* A single-provider client is not exposed to this. The attack needs a client that supports several
  authorization servers, one of which the attacker controls or has persuaded the client to register.
* Binding the code to a key would have stopped the redemption too — the attacker holds no DPoP key,
  see [authorization code binding](#authorization-code-binding-dpop_jkt) — but it would not tell the
  client anything was wrong.

## FAPI 2.0 security profile

`/fapi` checks the running configuration against the FAPI 2.0 security profile. The profile invents
nothing — it takes the mechanisms on the other pages and says which combination is mandatory: pushed
requests, PKCE, sender-constrained tokens, and client authentication that involves no shared secret.

**This demo is not FAPI 2.0 compliant, and the page says so.** Two server requirements fail:

| Requirement | Why it fails |
|---|---|
| The server requires pushed authorization requests | The profile wants every client rejected, not the willing ones. Both halves of RFC 9126's lock are implemented — [per client](#require_pushed_authorization_requests) and [server-wide](#require_pushed_authorization_requests-as-server-metadata) — and the server-wide one is off, so the row fails as configured rather than for want of a mechanism. It passes while that switch is on |
| All endpoints are served over TLS | The issuer is `http://localhost:8080`; only the mTLS listener on 8443 uses TLS |

A third — `iss` on the authorization response (RFC 9207) — used to fail and now passes, because
[the mix-up page](#mix-up-attack-defence-iss) implements it. The check asks the bean that actually
sends authorization responses, so it went green by the code changing, not the check.

One row is neither a pass nor a gap:

| Requirement | Why it is not applicable |
|---|---|
| Request objects are signed | FAPI 1.0 Advanced §5.2.2 required it; FAPI 2.0 took it out in favour of a pushed request with a short-lived `request_uri`, and its own comparison table gives the rationale as preventing pre-generated requests |

The row still reports what this server holds, because
[`require_signed_request_object`](#require_signed_request_object) is implemented here anyway: the
server-wide value read live from `RequestObjectPolicy`, and a count of the clients that
[set it for themselves](#require_signed_request_object-as-client-metadata). Reading the two rows
together is the point — FAPI 2.0 §5.3.1 says the server *"shall reject authorization requests sent
without [RFC9126]"*, which is the same lock one specification along, and that is the one this server
can turn for everybody and has not: `ClientSettings` has no
`require_pushed_authorization_requests` of its own (checked against the 7.1.1 sources), so both
halves here are custom, and RFC 9126 §5's server-wide value is `false` by default. The row reads that
value live, so it passes while the switch is on.

Per client, only `pkce-fapi-client` — registered specifically to the profile — meets every
requirement. The rest fail on purpose: each exists to demonstrate something the profile forbids, such
as a public client with no authentication, or a shared secret.

The checks read the live configuration (registered clients, authorization server settings) rather
than a hand-maintained list, so they stay honest as the demo changes. A profile check that only ever
passes is worth nothing.

## Refresh token binding

`/refresh-binding` asks whether the *refresh* token is bound to the DPoP key too. RFC 9449 §5 says a
refresh token issued to a **public** client must be — a client with no credentials has nothing else
to prove it is the one the token was issued to.

Getting one to ask about takes the device grant: the authorization code grant withholds refresh
tokens from public clients, so that is the only place here where the question arises. What comes back
is `token_type: DPoP`, a `cnf.jkt`, and a refresh token. Then, in order:

| Refresh request | Result |
|---|---|
| A proof from another key | `400 invalid_dpop_proof` — "jwk header is invalid" |
| **No proof at all** | `200`, `Bearer`, **no `cnf`** |
| A proof from the bound key, afterwards | `400 invalid_dpop_proof` — "jkt claim is missing" |

The second row is the gap: `OAuth2RefreshTokenAuthenticationProvider` verifies the proof's key
against the current access token's `cnf.jkt`, but only *if a proof was sent*. No proof, no
comparison, and the request is served as though DPoP had never been involved.

The third row is what that costs. **The binding lives on the access token, not on the refresh
token** — nothing stored says "this refresh token belongs to key K" — so the unbound token issued in
the second row becomes the one the check reads. Spending the refresh token once without a proof does
not merely slip past the binding: it removes it, and the client still holding the key is the one
locked out.

For a confidential client there is nothing to check and that is correct — the secret already says who
is asking. The rule exists for clients with no credential at all, which is why this page had to reach
for the device grant to find one.

Asking the question at all needed a small fix: a public client could be *issued* a refresh token by
the device grant and then had no way to spend it, since nothing in Spring Authorization Server
authenticates a public client on a refresh request. `DeviceClientAuthenticationConverter` now covers
that request as well as the two device endpoints.

## Certificate-bound refresh tokens

`/mtls-refresh` asks the same question of mTLS that the page above asks of DPoP, and gets a different
kind of answer. [The mTLS page](#certificate-bound-tokens-mtls) shows an access token carrying
`cnf.x5t#S256`; the refresh token outlives every access token it mints, so whether *it* can be spent
from anywhere is the question that decides what a leak costs.

`pkce-mtls-refresh-client` is registered for `self_signed_tls_client_auth` with the device grant —
client credentials issues no refresh token, so the existing mTLS client cannot be asked. The device
code is redeemed over the TLS listener, and the refresh token that comes back is then spent three
ways:

| Refresh request | Result |
|---|---|
| Over mTLS, with a certificate the server does not know | `401 invalid_client` |
| Over plain HTTP, with no certificate at all | `401 invalid_client` |
| Over mTLS, with the registered certificate | `200`, a new access token with the same `cnf.x5t#S256` |

The stranger's certificate is in the server's trust store on purpose. A TLS handshake that fails
demonstrates nothing about what the authorization server checks; this one succeeds, the request
arrives, and the refusal is the server's.

Notes:

* **Nothing checks a binding on refresh.** `OAuth2RefreshTokenAuthenticationProvider` compares a DPoP
  proof when one is sent and has no certificate handling at all — the string `x5t` does not appear in
  it. The two refusals above are client authentication failing, not a `cnf` comparison. For this
  client the certificate *is* the credential, so the outcome is the one RFC 8705 wants; the mechanism
  is not.
* **RFC 8705 §4's actual case cannot be reached here.** That section is about binding a refresh token
  to a certificate for a client that presents one *without* authenticating with it — a public client.
  Such a client would need a real comparison on refresh. Spring Authorization Server offers no way to
  bind without authenticating, so the case never arises in this demo, and the page says so rather
  than implying the server implements the harder half.
* **The device converter had to learn to stand aside.** `DeviceClientAuthenticationConverter` claims
  device and refresh requests carrying only a `client_id`, which is exactly what this client sends —
  it was authenticated as public and then refused for not being registered that way. It now returns
  `null` when the handshake carried a client certificate, leaving the request to Spring's own X.509
  converter.
* **The certificate is shared with `pkce-mtls-client`.** Both registrations point at the same
  published JWK set; the `client_id` in the request distinguishes them. That is a demo shortcut, not
  a recommendation.
* **Where `cnf.x5t#S256` is emitted was not found.** The claim is genuinely in the issued token — the
  page reads it back out — but the literal `x5t` appears nowhere in the Spring Authorization Server
  sources or in any jar on the classpath that was searched.

## What binds an ID token

`/idtoken-binding` asks of the ID token what the three pages above ask of the code, the refresh token
and the access token — and gets a different kind of answer. **No deployed specification binds an ID
token to a key.** What it has instead are claims saying where it belongs.

The page takes the session's own ID token and puts it through Spring Security's own
`OidcIdTokenValidator` five ways:

| Presented | Result |
|---|---|
| At the client it was issued to | accepted |
| Replayed at another client | **refused** — `aud`, `azp` |
| Replayed into another authorization request | **refused** — `invalid_nonce` |
| Paired with a different access token | accepted — nothing to compare |
| Presented by whoever is holding it | accepted — no `cnf` |

The last two are the point. Both refusals come from claims naming *where the token belongs*: one
client, one authorization request. Nothing names who is holding it.

Notes:

* **`at_hash` is absent, and that is legal.** OpenID Connect Core §3.1.3.6 requires it when the ID
  token comes from the *authorization* endpoint — implicit and hybrid, where the access token travels
  through the browser — and makes it OPTIONAL from the token endpoint, which is the only place this
  server issues one. Spring Authorization Server never emits it: the string `at_hash` appears nowhere
  in its sources. The page computes what the claim *would* have held for the real access token and
  for the substituted one, so the absence is visible rather than asserted.
* **Spring Security's client would not check it either.** `OidcIdTokenValidator.validate` takes one
  argument, the ID token; the access token is not in scope. A test pins that: the class declares
  exactly one non-bridge `validate`, and its only parameter is `Jwt`. The reasoning holds for the
  code flow — both tokens arrive in one response over one connection to a server the client
  authenticated — and stops holding the moment anything else carries that pair onwards.
* **The `nonce` claim is a hash.** Spring's client generates a nonce, sends `createHash(nonce)` in
  the authorization request, and keeps the value. The authorization server only ever sees the hash.
* **There is no `cnf`, and no specification to add one to.** DPoP binds access and refresh tokens;
  RFC 8705 binds access tokens; neither mentions ID tokens. The one specification that did — OpenID
  Connect Token Bound Authentication, with `cnf.tbh` naming a TLS Token Binding (RFC 8471) — went
  nowhere when browsers dropped Token Binding.
* **What it is bound to is a session.** The `sid` claim names the authorization server session, which
  is what [back-channel logout](#back-channel-logout) ends and what the session iframe watches. Not a
  holder — a moment.

## Authorization code binding (`dpop_jkt`)

`/code-binding` demonstrates RFC 9449 section 10. An authorization code is a bearer credential for
the seconds it lives, and PKCE binds it to a one-time secret. `dpop_jkt` binds it to the client's
DPoP key instead — the same key the issued token ends up bound to, so one private key holds the
whole flow together.

The page runs the flow twice and keeps both results side by side. Every redemption sends the
**correct `code_verifier`**: the attacker being modelled holds the code *and* the PKCE secret, which
is the only situation where a second binding adds anything.

With `dpop_jkt` in the authorization request, one code is then redeemed four times:

| Attempt | Result |
|---|---|
| The code and the verifier alone, no proof | `400 invalid_grant` |
| A well-formed proof signed by another key | `400 invalid_grant` |
| A proof signed by the bound key | `200`, `token_type: DPoP`, `cnf.jkt` equal to `dpop_jkt` |
| The same code again | `400 invalid_grant` — it was spent by the third |

Without `dpop_jkt`, the same code redeems on the first attempt with no proof at all, as a plain
`Bearer` token. That is not a flaw in PKCE; it is the gap `dpop_jkt` closes.

Notes:

* **Spring Authorization Server has no notion of `dpop_jkt`.** It stores the parameter with the rest
  of the authorization request and never reads it again, so `DpopBoundAuthorizationCodeFilter` sits
  in front of the token endpoint, looks the code up, and enforces the binding. Running *before* the
  endpoint is deliberate: a refused request leaves the code outstanding, which is why the third
  attempt above can still succeed after the first two were turned away.
* The filter verifies the proof's signature before trusting the key in its header. A thumbprint is
  public, so anyone can put the victim's public key in a proof — what they cannot do is sign with it.
* RFC 9449 does not name an error code for the mismatch. This server answers `invalid_grant`, since
  the code is what cannot be redeemed.
* The same section warns that the protection is only as good as the key's uniqueness, so each run
  generates its own key, verifier and state.
* Section 10.1 covers the parameter inside a pushed request, where it travels in the POST body.

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
│   ├── StrongResourceSecurityConfig.java  /resource/** — a bearer token, then a look at its acr
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
│   ├── MtlsJwkSetController.java        /mtls-jwks.json, the client's certificate
│   ├── TokenExchangeController.java     /exchange
│   ├── RichAuthorizationController.java /rar
│   ├── CibaController.java              /ciba, /ciba/poll, /ciba/approve
│   ├── BackchannelAuthenticationController.java  /backchannel/authenticate
│   ├── StepUpController.java            /stepup, /stepup/verify
│   ├── JarController.java               /jar
│   ├── JarJwkSetController.java         /jar-jwks.json, the request object signing key
│   ├── FapiController.java              /fapi
│   ├── AuthorizationCodeBindingController.java  /code-binding and its own callback
│   ├── RefreshTokenBindingController.java  /refresh-binding
│   ├── MtlsRefreshController.java       /mtls-refresh
│   ├── IdTokenBindingController.java    /idtoken-binding
│   ├── StepUpChallengeController.java   /stepup-challenge
│   ├── FreshnessController.java         /freshness
│   ├── SilentAuthController.java        /silent-auth
│   ├── RequestUriController.java        /request-uri
│   ├── RarEnforcementController.java    /rar-enforcement
│   ├── DpopNonceController.java         /dpop-nonce
│   ├── IntrospectionJwtController.java  /introspection-jwt
│   ├── JarmController.java              /jarm
│   ├── JarmAlgorithmController.java     /jarm-alg
│   ├── JarmEncryptionController.java    /jarm-enc
│   ├── JarmEncryptionMethodController.java  /jarm-enc-method
│   ├── RequestObjectEncryptionController.java  /jar-enc
│   ├── RequestObjectSigningAlgController.java  /jar-alg
│   ├── RequestObjectEncryptionAlgController.java  /jar-enc-alg
│   ├── RequestObjectEncryptionMethodController.java  /jar-enc-method
│   ├── UnsignedRequestObjectController.java  /jar-none
│   ├── RequiredRequestObjectController.java  /jar-required
│   ├── ClientRequiredRequestObjectController.java  /jar-client-required
│   ├── ParRequiredController.java       /par-required
│   ├── ServerParRequiredController.java  /par-server-required
│   ├── RequestUriMetadataController.java  /request-uri-metadata
│   ├── RequestUriRegistrationController.java  /request-uri-registration
│   ├── RegisteredRequestUriController.java  /request-uris
│   ├── AdvertisedAlgController.java     /jar-alg-values
│   ├── EncryptionAlgValuesController.java  /jar-enc-alg-values
│   ├── EncryptionMethodValuesController.java  /jar-enc-method-values
│   ├── HostedRequestObjectController.java  /hosted/**, the client's own hosting
│   ├── JarmClientJwkSetController.java  /jarm-client-jwks.json — the client's own keys
│   ├── NonceApiController.java          /nonce/me — DPoP, and a nonce in every proof
│   ├── PaymentApiController.java        /payments — the operation the grant was about
│   ├── StrongResourceController.java    /resource/transfer, the operation being protected
│   ├── MixUpController.java             /mixup and its own callback
│   ├── MixUpAttackerController.java     /mixup/attacker/**, the rogue authorization server
│   ├── AuthorizationServerMetadataController.java  /metadata
│   ├── DynamicClientRegistrationController.java   /dynamic-registration
│   ├── LogoutRevocationController.java   /logout-revocation
│   ├── BackChannelLogoutController.java  /backchannel-logout
│   ├── FrontChannelLogoutController.java /frontchannel-logout
│   ├── ClientFrontChannelLogoutController.java  the client endpoint the iframes load
│   ├── SessionManagementController.java  /session-management
│   └── CheckSessionIframeController.java the OP iframe itself
├── entity|repository/                   users
├── service/
│   ├── JpaUserDetailsService.java       authenticates against MySQL
│   ├── TokenRefreshService.java         runs the refresh_token grant on demand
│   ├── DeviceFlowService.java           drives RFC 8628 over HTTP
│   ├── TokenAdminService.java           introspects and revokes as the confidential client
│   ├── PushedAuthorizationRequestService.java  pushes to /oauth2/par
│   ├── DpopService.java                 signs proofs and proves a stolen token is useless
│   ├── ClientAssertionService.java      authenticates with a signed JWT, three ways
│   ├── MtlsService.java                 calls the TLS endpoint with and without a certificate
│   ├── TokenExchangeService.java        impersonation, delegation, and one that must fail
│   ├── CibaService.java                 pending backchannel requests and their outcome
│   ├── CibaClientService.java           the client side: open a request, then poll
│   ├── StepUpService.java               adds a second factor to the session
│   ├── FapiComplianceService.java       checks the configuration against the profile
│   ├── AuthorizationCodeBindingService.java  runs the code binding flow and redeems the code
│   ├── RefreshTokenBindingService.java  device grant with a key, then three refreshes
│   ├── MtlsRefreshService.java          device grant over mTLS, then three connections
│   ├── IdTokenBindingService.java       the session's ID token, presented five ways
│   ├── StepUpChallengeService.java      calls the operation, keeps the challenge it was given
│   ├── FreshnessService.java            a probe session that asks max_age three ways
│   ├── SilentAuthService.java           a probe session that asks prompt=none five ways
│   ├── RequestUriService.java           pushes one request and spends it five ways
│   ├── RarEnforcementService.java       two tokens, five payment instructions
│   ├── DpopNonceService.java            a bound token, then five calls with five proofs
│   ├── IntrospectionJwtService.java     one token, introspected four ways
│   ├── JarmService.java                 one authorization, asked for seven ways
│   ├── JarmAlgorithmService.java        the same request from three registrations
│   ├── JarmEncryptionService.java       one answer signed, one signed and encrypted
│   ├── JarmEncryptionMethodService.java  the same answer wrapped three ways
│   ├── RequestObjectEncryptionService.java  the same request sent three ways
│   ├── RequestObjectSigningAlgService.java  the same request signed five ways
│   ├── RequestObjectEncryptionAlgService.java  the same request wrapped six ways
│   ├── RequestObjectEncryptionMethodService.java  the same request encrypted six ways
│   ├── UnsignedRequestObjectService.java  six request objects, five unsigned
│   ├── RequiredRequestObjectService.java  four requests, under both settings
│   ├── ClientRequiredRequestObjectService.java  registers two clients, then asks them
│   ├── ParRequiredService.java          five ways to start one request
│   ├── ServerParRequiredService.java    four requests, under both settings
│   ├── RequestUriMetadataService.java   four ways to point at one object
│   ├── RequestUriRegistrationService.java  four URLs, under both settings
│   ├── RegisteredRequestUriService.java  registers a list, then tests it
│   ├── AdvertisedAlgService.java        five algorithms against the lists
│   ├── EncryptionAlgValuesService.java  five objects, three published keys
│   ├── EncryptionMethodValuesService.java  every advertised pair, twice
│   ├── MixUpService.java                the client side of the mix-up: start, then decide
│   ├── MixUpAttackerService.java        the attacker's: forward the request, take the code
│   ├── AuthorizationServerMetadataService.java  reads the published documents back
│   ├── DynamicClientRegistrationService.java  registers a client, and fails to five ways
│   ├── LogoutRevocationService.java     signs out, then looks at the tokens
│   ├── BackChannelLogoutService.java    mints logout tokens and posts them
│   └── FrontChannelLogoutService.java   builds the iframe document, and probes it
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
    ├── MtlsAttempt.java
    ├── TokenExchangeAttempt.java
    ├── RichAuthorizationDetail.java     parses and summarises authorization_details
    ├── RichAuthorizationRequestValidator.java  refuses types the server does not implement
    ├── Ciba*.java                       the CIBA grant, added to the token endpoint
    ├── AuthenticationContextLevel.java  factors in, acr and amr out
    ├── StepUpRequiredFilter.java        enforces acr_values at the authorization endpoint
    ├── JarRequestSigner.java            signs RFC 9101 request objects, by name, on a
    │                                    curve, or not at all
    ├── JwtSecuredAuthorizationRequestFilter.java  unwraps and verifies one against the
    │                                        algorithms its client registered, and uses only
    │                                        what it carries
    ├── FapiCheck.java                   one requirement, its outcome, and what was observed
    ├── DpopBoundAuthorizationCodeFilter.java  enforces dpop_jkt at the token endpoint
    ├── IssuerIdentifierResponseHandler.java  puts iss on every authorization response
    ├── MixUpStep.java                   one move in a mix-up run, and who made it
    ├── MixUpRun.java
    ├── PendingMixUp.java                what the client wrote down before sending the user away
    ├── ServerMetadataCustomizer.java    adds what this application supports to both documents
    ├── MetadataEntry.java               one published field, its requirement level and its source
    ├── MetadataComparison.java
    ├── DiscoveryAttempt.java
    ├── RegistrationAttempt.java         one request to the registration endpoint
    ├── RegistrationRun.java
    ├── RevokingLogoutHandler.java       revokes the session's tokens as part of logging out
    ├── LogoutStep.java
    ├── LogoutRevocationRun.java
    ├── LogoutTokenFactory.java          signs logout tokens, and one that must not verify
    ├── BackChannelAttempt.java
    ├── BackChannelLogoutRun.java
    ├── FrontChannelLogoutTarget.java    one client's front-channel URI
    ├── FrontChannelProbe.java
    ├── FrontChannelLogoutRun.java
    ├── OpBrowserState.java              the cookie, and the session_state computed from it
    ├── PendingCodeBinding.java          what the client remembers between the two legs
    ├── PendingRefreshBinding.java       the device codes, and the key they were asked for with
    ├── PendingMtlsRefresh.java          the device codes asked for over the TLS listener
    ├── MtlsRefreshAttempt.java          one refresh request, and which connection made it
    ├── MtlsRefreshRun.java              what was issued, and how the three attempts went
    ├── IdTokenCheck.java                one way of presenting an ID token, and what decided it
    ├── IdTokenBindingRun.java           the claims, the hashes that are not there, the checks
    ├── StepUpChallenge.java             a WWW-Authenticate header, read the way a client reads it
    ├── InsufficientUserAuthenticationHandler.java  the 401 Spring Security does not write
    ├── ResourceCallAttempt.java         one call to the protected operation
    ├── StepUpChallengeRun.java          the calls so far, and the challenge still outstanding
    ├── AuthenticationFreshness.java     auth_time, and whether a max_age is met
    ├── MaxAgeRequiredFilter.java        enforces max_age at the authorization endpoint
    ├── FreshnessAttempt.java            one ask, and what auth_time did
    ├── FreshnessRun.java                the three asks of one probe
    ├── PromptNoneFilter.java            answers prompt=none instead of showing a login page
    ├── SilentAuthAttempt.java           one silent question, and what came back
    ├── SilentAuthRun.java               the five questions of one probe
    ├── RequestUriAttempt.java           one way of spending a pushed reference
    ├── RequestUriRun.java               the reference, its expiry, and the five attempts
    ├── PaymentAuthorizer.java           holds an instruction against authorization_details
    ├── PaymentInstruction.java          the amount, currency and account asked for
    ├── AuthorizationDetailsDecision.java  allowed or refused, and why
    ├── RarEnforcementAttempt.java       one instruction and the answer it got
    ├── RarEnforcementRun.java           the granted detail and the five instructions
    ├── DpopNonceStore.java              issues nonces, and spends them once
    ├── DpopNonceRequiredFilter.java     the use_dpop_nonce challenge Spring does not write
    ├── DpopNonceAttempt.java            one call, its nonce, and the answer
    ├── DpopNonceRun.java                the key, the token, and the five calls
    ├── IntrospectionJwtResponseHandler.java  signs the introspection response when asked
    ├── IntrospectionResponseAttempt.java  one answer, signed or not
    ├── IntrospectionJwtRun.java         the four answers
    ├── JarmResponseFilter.java          repackages the authorization response as a signed JWT
    ├── JarmAttempt.java                 one answer, and whether it could be checked
    ├── JarmRun.java                     the seven answers
    ├── JarmAlgorithmAttempt.java        one client, its setting, and the header it got
    ├── JarmAlgorithmRun.java            the three registrations and the published keys
    ├── JarmClientKeys.java              the client's key pair, and how it decrypts
    ├── JarmEncryptionRun.java           the two answers, the header, and what was inside
    ├── JarmEncryptionMethodAttempt.java  one registration, and the shape it produced
    ├── JarmEncryptionMethodRun.java     the three shapes side by side
    ├── RequestObjectAttempt.java        one request object, and what it gave away
    ├── RequestObjectRun.java            the three request objects
    ├── SigningAlgAttempt.java           one object, its registration and its header
    ├── SigningAlgRun.java               the five request objects
    ├── RequestEncryptionAlgAttempt.java  one object, its registration and its JWE header
    ├── RequestEncryptionAlgRun.java     the six request objects
    ├── RequestEncryptionMethodAttempt.java  one object, its registration and its shape
    ├── RequestEncryptionMethodRun.java  the six request objects, and what padded
    ├── UnsignedRequestAttempt.java      one object with no signature to check
    ├── UnsignedRequestRun.java          the six, and which were acted on
    ├── RequestObjectPolicy.java         RFC 9101 §10.5's server-wide switch, held in one place
    ├── RequiredRequestAttempt.java      one request, and its fate under each setting
    ├── RequiredRequestRun.java          the four, and what the documents said
    ├── RequestObjectClientRegistrationConverters.java  keeps and echoes the two
    │                                    request object settings a registration carries
    ├── ClientRequiredAttempt.java       one request to a client that asked for the lock
    ├── ClientRequiredRun.java           the six, and the registration behind two of them
    ├── PushedAuthorizationRequiredFilter.java  refuses a request that did not arrive
    │                                    through the pushed endpoint
    ├── ParRequiredAttempt.java          one request, and which check refused it
    ├── ParRequiredRun.java              the five, and the published server-wide value
    ├── PushedAuthorizationPolicy.java   RFC 9126 §5's server-wide switch, in one place
    ├── ServerParRequiredAttempt.java    one request, and its fate under each setting
    ├── ServerParRequiredRun.java        the four, the documents and the profile row
    ├── RequestUriMetadataAttempt.java   one way of pointing, and what came of it
    ├── RequestUriMetadataRun.java       the four, beside what the documents claim
    ├── RequestUriFetcher.java           RFC 9101 §5.2.3's GET, with §10.4.1's precautions
    ├── RequestUriPolicy.java            require_request_uri_registration, in one place
    ├── RequestUriRegistrationAttempt.java  one URL, and its fate under each setting
    ├── RequestUriRegistrationRun.java   the four, and what the documents said
    ├── RegisteredRequestUriAttempt.java  one URL, and whether it was on the list
    ├── RegisteredRequestUriRun.java     the list as sent, echoed and held
    ├── AdvertisedAlgAttempt.java        one algorithm, advertised and registered or not
    ├── AdvertisedAlgRun.java            the five, beside the three published lists
    ├── EncryptionAlgValuesAttempt.java  one object, its algorithm and its key
    ├── EncryptionAlgValuesRun.java      the five, beside the published keys
    ├── EncryptionMethodCell.java        one pair, and what became of it
    ├── EncryptionMethodGrid.java        one client's four pairs
    ├── EncryptionMethodValuesRun.java   both grids, and the pair off the list
    ├── RefreshBindingAttempt.java
    ├── RefreshBindingRun.java
    ├── CodeBindingAttempt.java
    └── CodeBindingRun.java

src/main/resources/db/migration/
├── V1_13092026_1256__create_user_tables.sql
├── V2_13092026_1257__create_oauth2_authorization_server_tables.sql
├── V3_13092026_1258__create_oauth2_authorized_client_table.sql
└── V4_13092026_1610__create_ciba_request_table.sql
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
  gets a 500. Reachable just by pressing a sign-in button twice, or by starting a run on
  `/code-binding` with a login already in the session. `RestartOAuth2LoginFilter` clears the session
  and starts the flow clean; it is given every URI this app starts an authorization request from.
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
