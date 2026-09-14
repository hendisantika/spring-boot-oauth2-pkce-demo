package id.my.hendisantika.oauth2pkcedemo.config;

import id.my.hendisantika.oauth2pkcedemo.controller.AuthorizationCodeBindingController;
import id.my.hendisantika.oauth2pkcedemo.controller.FreshnessController;
import id.my.hendisantika.oauth2pkcedemo.controller.DpopNonceController;
import id.my.hendisantika.oauth2pkcedemo.controller.JarmClientJwkSetController;
import id.my.hendisantika.oauth2pkcedemo.controller.JarmController;
import id.my.hendisantika.oauth2pkcedemo.security.JarmResponseFilter;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.controller.RarEnforcementController;
import id.my.hendisantika.oauth2pkcedemo.controller.RequestUriController;
import id.my.hendisantika.oauth2pkcedemo.controller.SilentAuthController;
import id.my.hendisantika.oauth2pkcedemo.controller.MixUpController;
import id.my.hendisantika.oauth2pkcedemo.controller.ClientJwkSetController;
import id.my.hendisantika.oauth2pkcedemo.controller.MtlsJwkSetController;
import id.my.hendisantika.oauth2pkcedemo.security.CibaAuthenticationToken;
import id.my.hendisantika.oauth2pkcedemo.entity.User;
import id.my.hendisantika.oauth2pkcedemo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.UUID;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 12.56
 */
@Slf4j
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class DemoDataInitializer {

    /**
     * Seeds the demo users and both registered clients. Every write is idempotent, so restarting
     * against an existing MySQL volume is a no-op.
     */
    @Bean
    public ApplicationRunner demoDataRunner(UserRepository userRepository,
                                            PasswordEncoder passwordEncoder,
                                            RegisteredClientRepository registeredClientRepository,
                                            DemoProperties properties) {
        return args -> {
            seedUsers(userRepository, passwordEncoder, properties);
            seedRegisteredClient(registeredClientRepository, passwordEncoder, properties, properties.client());
            seedRegisteredClient(registeredClientRepository, passwordEncoder, properties,
                    properties.confidentialClient());
            seedAssertionClient(registeredClientRepository, properties);
            seedMtlsClient(registeredClientRepository, properties);
            seedExchangeClient(registeredClientRepository, passwordEncoder, properties);
            seedCibaClient(registeredClientRepository, passwordEncoder, properties);
            seedFapiClient(registeredClientRepository, properties);
            seedCodeBindingClient(registeredClientRepository, properties);
            seedMixUpClient(registeredClientRepository, properties);
            seedRegistrarClient(registeredClientRepository, passwordEncoder, properties);
            seedRelayClient(registeredClientRepository, passwordEncoder, properties);
            seedMtlsRefreshClient(registeredClientRepository, properties);
            seedFreshnessClient(registeredClientRepository, properties);
            seedSilentClient(registeredClientRepository, properties);
            seedRequestUriClient(registeredClientRepository, properties);
            seedRarClient(registeredClientRepository, properties);
            seedDpopNonceClient(registeredClientRepository, properties);
            seedJarmClient(registeredClientRepository, properties);
            seedJarmVariant(registeredClientRepository, properties, properties.jarmEcClient(), "ES256");
            seedJarmVariant(registeredClientRepository, properties, properties.jarmNoneClient(), "none");
            seedJarmEncryptedClient(registeredClientRepository, properties);
            seedJarPsClient(registeredClientRepository, properties);
            seedJarmEncryptionMethod(registeredClientRepository, properties,
                    properties.jarmGcmClient(), "A256GCM");
            seedJarmEncryptionMethod(registeredClientRepository, properties,
                    properties.jarmUnsupportedEncClient(), "A192CBC-HS384");
        };
    }

    @Transactional
    void seedUsers(UserRepository userRepository, PasswordEncoder passwordEncoder, DemoProperties properties) {
        for (DemoProperties.DemoUser demoUser : properties.demoUsers()) {
            if (userRepository.existsByUsername(demoUser.username())) {
                continue;
            }
            userRepository.save(User.builder()
                    .username(demoUser.username())
                    .password(passwordEncoder.encode(demoUser.password()))
                    .fullName(demoUser.fullName())
                    .email(demoUser.email())
                    .enabled(true)
                    .authorities(new LinkedHashSet<>(demoUser.authorities()))
                    .build());
            log.info("Seeded demo user [{}]", demoUser.username());
        }
    }

    /**
     * A client that authenticates with a signed JWT instead of a secret. The server is told where to
     * fetch its public keys and which algorithm to expect; nothing confidential is stored either
     * side. It uses the client credentials grant because there is no user in this exchange at all.
     */
    void seedAssertionClient(RegisteredClientRepository registeredClientRepository,
                             DemoProperties properties) {
        DemoProperties.Client client = properties.assertionClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientSettings(ClientSettings.builder()
                        .jwkSetUrl(properties.issuerUri() + ClientJwkSetController.CLIENT_JWK_SET_URI)
                        .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered private_key_jwt client [{}]", client.clientId());
    }

    /**
     * A client that authenticates with a TLS client certificate. Nothing in the request identifies
     * it - the transport already did. The token it receives is bound to that certificate, so it can
     * only be used over a connection presenting the same one.
     */
    void seedMtlsClient(RegisteredClientRepository registeredClientRepository, DemoProperties properties) {
        DemoProperties.Client client = properties.mtlsClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientSettings(ClientSettings.builder()
                        .jwkSetUrl(properties.issuerUri() + MtlsJwkSetController.MTLS_JWK_SET_URI)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        // RFC 8705 section 3: bind the access token to the client certificate.
                        .x509CertificateBoundAccessTokens(true)
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered mTLS client [{}]", client.clientId());
    }

    /**
     * A downstream service that exchanges a token it was given for one scoped to its own work. It
     * also holds the client credentials grant so it can mint an actor token to present alongside,
     * which is what turns impersonation into delegation.
     */
    void seedExchangeClient(RegisteredClientRepository registeredClientRepository,
                            PasswordEncoder passwordEncoder, DemoProperties properties) {
        DemoProperties.Client client = properties.exchangeClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSecret(passwordEncoder.encode(client.clientSecret()))
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered token exchange client [{}]", client.clientId());
    }

    /**
     * A client that authenticates a user it can name but cannot reach: it opens a backchannel
     * request and polls while the user approves somewhere else. The grant type is registered so the
     * token endpoint accepts it; everything behind it is implemented outside the framework.
     */
    void seedCibaClient(RegisteredClientRepository registeredClientRepository,
                        PasswordEncoder passwordEncoder, DemoProperties properties) {
        DemoProperties.Client client = properties.cibaClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSecret(passwordEncoder.encode(client.clientSecret()))
                .authorizationGrantType(CibaAuthenticationToken.CIBA_GRANT_TYPE)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered CIBA client [{}]", client.clientId());
    }

    /**
     * A client shaped to the FAPI 2.0 security profile, so the compliance page has something that
     * passes next to the ones that do not: no shared secret, PKCE required, refresh tokens rotated,
     * and access tokens bound to the client's certificate.
     */
    void seedFapiClient(RegisteredClientRepository registeredClientRepository, DemoProperties properties) {
        DemoProperties.Client client = properties.fapiClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                // The profile permits private_key_jwt or mTLS; a client secret is not an option.
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(properties.issuerUri() + "/login/oauth2/code/" + client.registrationId())
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(true)
                        .jwkSetUrl(properties.issuerUri() + ClientJwkSetController.CLIENT_JWK_SET_URI)
                        .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .reuseRefreshTokens(false)
                        .x509CertificateBoundAccessTokens(true)
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered FAPI client [{}]", client.clientId());
    }

    /**
     * A public client whose authorization codes can be bound to a DPoP key. It is registered
     * separately from the other public client so the binding demo owns its own redirect URI, and so
     * that a code redeemed there cannot be confused with one from the browser login.
     */
    void seedCodeBindingClient(RegisteredClientRepository registeredClientRepository,
                               DemoProperties properties) {
        DemoProperties.Client client = properties.codeBindingClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(properties.issuerUri()
                        + AuthorizationCodeBindingController.CALLBACK_URI)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        // Off so that one click makes one round trip. Consent is demonstrated by
                        // every other authorization code page; this one is about the code itself.
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered code binding client [{}]", client.clientId());
    }

    /**
     * The client the JARM page drives. Nothing about its registration says anything about response
     * modes - the demo reads the request parameter instead, because there is no client setting for
     * it to read.
     */
    void seedJarmClient(RegisteredClientRepository registeredClientRepository,
                        DemoProperties properties) {
        DemoProperties.Client client = properties.jarmClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(properties.issuerUri() + JarmController.CALLBACK_URI)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered JARM client [{}]", client.clientId());
    }

    /**
     * A JARM client that differs from the last only in the algorithm on its registration. JARM puts
     * that choice in {@code authorization_signed_response_alg}; Spring Authorization Server has no
     * setting of its own for it, so it travels as a custom one.
     */
    void seedJarmVariant(RegisteredClientRepository registeredClientRepository,
                         DemoProperties properties, DemoProperties.Client client, String algorithm) {
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(properties.issuerUri() + JarmController.CALLBACK_URI)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .setting(JarmResponseFilter.SIGNED_RESPONSE_ALG, algorithm)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered JARM client [{}] for {}", client.clientId(), algorithm);
    }

    /**
     * The JARM client whose responses are encrypted as well as signed. The key is the client's, not
     * the server's, so the registration points at where the client publishes it - the same
     * {@code jwkSetUrl} a client would use for authentication keys, which is where OpenID Connect
     * puts both.
     */
    void seedJarmEncryptedClient(RegisteredClientRepository registeredClientRepository,
                                 DemoProperties properties) {
        DemoProperties.Client client = properties.jarmEncryptedClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(properties.issuerUri() + JarmController.CALLBACK_URI)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .jwkSetUrl(properties.issuerUri()
                                + JarmClientJwkSetController.JARM_CLIENT_JWK_SET_URI)
                        .setting(JarmResponseFilter.ENCRYPTED_RESPONSE_ALG, "RSA-OAEP-256")
                        // enc is left out on purpose: JARM defaults it, and the page shows that.
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered encrypted JARM client [{}]", client.clientId());
    }

    /**
     * An encrypting JARM client that differs from the last only in the content encryption it named.
     * {@code alg} stays RSA-OAEP-256 throughout: the two settings are chosen independently, and the
     * page exists to show what changes when only the second one does.
     */
    void seedJarmEncryptionMethod(RegisteredClientRepository registeredClientRepository,
                                  DemoProperties properties, DemoProperties.Client client,
                                  String encryptionMethod) {
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(properties.issuerUri() + JarmController.CALLBACK_URI)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .jwkSetUrl(properties.issuerUri()
                                + JarmClientJwkSetController.JARM_CLIENT_JWK_SET_URI)
                        .setting(JarmResponseFilter.ENCRYPTED_RESPONSE_ALG, "RSA-OAEP-256")
                        .setting(JarmResponseFilter.ENCRYPTED_RESPONSE_ENC, encryptionMethod)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered JARM client [{}] for {}", client.clientId(), encryptionMethod);
    }

    /**
     * A client that registered PS256 for its request objects. It publishes the same key as the other
     * JAR client - one RSA key carries either algorithm - so the only difference between them is the
     * word on the registration, which is exactly what the page is about.
     */
    void seedJarPsClient(RegisteredClientRepository registeredClientRepository,
                         DemoProperties properties) {
        DemoProperties.Client client = properties.jarPsClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(properties.issuerUri() + "/login/oauth2/code/" + client.registrationId())
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .setting(JwtSecuredAuthorizationRequestFilter.SIGNING_ALG_SETTING, "PS256")
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered PS256 request object client [{}]", client.clientId());
    }

    /**
     * The client the DPoP nonce page drives. Public: DPoP binds a token to a key, which is exactly
     * the case where the client has no secret to bind it to instead.
     */
    void seedDpopNonceClient(RegisteredClientRepository registeredClientRepository,
                             DemoProperties properties) {
        DemoProperties.Client client = properties.dpopNonceClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(properties.issuerUri() + DpopNonceController.CALLBACK_URI)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered DPoP nonce client [{}]", client.clientId());
    }

    /**
     * The client the RAR enforcement page drives. Confidential, because authorization_details are
     * pushed rather than put in a URL, and with consent off so that one run is one round trip.
     */
    void seedRarClient(RegisteredClientRepository registeredClientRepository,
                       DemoProperties properties) {
        DemoProperties.Client client = properties.rarClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientSecret("{noop}" + client.clientSecret())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(properties.issuerUri() + RarEnforcementController.CALLBACK_URI)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered RAR client [{}]", client.clientId());
    }

    /**
     * The client the request_uri page drives. Confidential, because the pushed authorization request
     * endpoint will not talk to a client that cannot authenticate, and with consent off so that one
     * pushed request is spent by one round trip rather than by a screen.
     */
    void seedRequestUriClient(RegisteredClientRepository registeredClientRepository,
                              DemoProperties properties) {
        DemoProperties.Client client = properties.requestUriClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientSecret("{noop}" + client.clientSecret())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(properties.issuerUri() + RequestUriController.CALLBACK_URI)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered request_uri client [{}]", client.clientId());
    }

    /**
     * The client the prompt=none probe drives. Consent is required on purpose: silent
     * authentication turns on whether the user has already agreed, and the page shows both sides of
     * that.
     */
    void seedSilentClient(RegisteredClientRepository registeredClientRepository,
                          DemoProperties properties) {
        DemoProperties.Client client = properties.silentClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(properties.issuerUri() + SilentAuthController.CALLBACK_URI)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered silent client [{}]", client.clientId());
    }

    /**
     * The client the freshness probe drives. Public and PKCE like the browser clients, with consent
     * off so that one run is one round trip - the page is about max_age, not about consent.
     */
    void seedFreshnessClient(RegisteredClientRepository registeredClientRepository,
                             DemoProperties properties) {
        DemoProperties.Client client = properties.freshnessClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(properties.issuerUri() + FreshnessController.CALLBACK_URI)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered freshness client [{}]", client.clientId());
    }

    /**
     * The client as the honest server knows it. Registered separately so the mix-up demo owns its
     * own redirect URI - the one the attacker forwards the user's browser to, and the one the
     * authorization code is therefore delivered to.
     */
    void seedMixUpClient(RegisteredClientRepository registeredClientRepository,
                         DemoProperties properties) {
        DemoProperties.Client client = properties.mixUpClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(properties.issuerUri() + MixUpController.CALLBACK_URI)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        // Off so a run is one round trip. The mix-up fools the client, not the
                        // user - what the user sees at the honest server is entirely genuine.
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered mix-up client [{}]", client.clientId());
    }

    /**
     * The one client allowed to create others. RFC 7591 section 3 leaves the registration endpoint's
     * protection open: this server requires an access token, and this is what obtains one.
     */
    void seedRegistrarClient(RegisteredClientRepository registeredClientRepository,
                             PasswordEncoder passwordEncoder, DemoProperties properties) {
        DemoProperties.Client client = properties.registrarClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSecret(passwordEncoder.encode(client.clientSecret()))
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder()
                        // Short-lived on purpose: an initial access token is spent as soon as it is
                        // used, so there is nothing to gain from a long one.
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered registrar client [{}]", client.clientId());
    }

    /**
     * A second service holding the same grants as the exchange client. Registered so the demo has a
     * party that is allowed to exchange tokens in general and still refused for this user, which is
     * the only way to show what may_act decides.
     */
    void seedRelayClient(RegisteredClientRepository registeredClientRepository,
                         PasswordEncoder passwordEncoder, DemoProperties properties) {
        DemoProperties.Client client = properties.relayClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSecret(passwordEncoder.encode(client.clientSecret()))
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered relay client [{}]", client.clientId());
    }

    /**
     * An mTLS client that is issued a refresh token. The one on the mTLS page holds only the client
     * credentials grant, which never produces one; this holds the device grant, which is the way a
     * refresh token can be obtained here without a browser redirect belonging to the client.
     */
    void seedMtlsRefreshClient(RegisteredClientRepository registeredClientRepository,
                               DemoProperties properties) {
        DemoProperties.Client client = properties.mtlsRefreshClient();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .clientSettings(ClientSettings.builder()
                        .jwkSetUrl(properties.issuerUri() + MtlsJwkSetController.MTLS_JWK_SET_URI)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        // RFC 8705 section 3: the access token is bound to the certificate. Whether
                        // the refresh token is too is what the page asks.
                        .x509CertificateBoundAccessTokens(true)
                        .reuseRefreshTokens(false)
                        .build());
        client.scopes().forEach(builder::scope);

        registeredClientRepository.save(builder.build());
        log.info("Registered mTLS refresh client [{}]", client.clientId());
    }

    void seedRegisteredClient(RegisteredClientRepository registeredClientRepository,
                              PasswordEncoder passwordEncoder,
                              DemoProperties properties,
                              DemoProperties.Client client) {
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // Device flow targets input-constrained public clients, so only that one gets it.
                .authorizationGrantTypes(grantTypes -> {
                    if (client.isPublic()) {
                        grantTypes.add(AuthorizationGrantType.DEVICE_CODE);
                    }
                })
                .redirectUri(properties.issuerUri() + "/login/oauth2/code/" + client.registrationId())
                .postLogoutRedirectUri(properties.issuerUri() + "/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .clientSettings(ClientSettings.builder()
                        // Reject any authorization request that arrives without a code_challenge.
                        // Set on both clients: PKCE is not only for public ones.
                        .requireProofKey(true)
                        .requireAuthorizationConsent(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofHours(8))
                        // Rotate the refresh token on every exchange, so replaying an old one fails.
                        .reuseRefreshTokens(false)
                        .build());

        if (client.isPublic()) {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientSecret(passwordEncoder.encode(client.clientSecret()));
        }

        registeredClientRepository.save(builder.build());
        log.info("Registered {} client [{}]", client.isPublic() ? "public" : "confidential", client.clientId());
    }
}
