package id.my.hendisantika.oauth2pkcedemo.config;

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
