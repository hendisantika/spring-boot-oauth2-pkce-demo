package id.my.hendisantika.oauth2pkcedemo.config;

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
     * Seeds the demo users and the PKCE-only client. Both writes are idempotent, so restarting
     * against an existing MySQL volume is a no-op.
     */
    @Bean
    public ApplicationRunner demoDataRunner(UserRepository userRepository,
                                            PasswordEncoder passwordEncoder,
                                            RegisteredClientRepository registeredClientRepository,
                                            DemoProperties properties) {
        return args -> {
            seedUsers(userRepository, passwordEncoder, properties);
            seedRegisteredClient(registeredClientRepository, properties);
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

    void seedRegisteredClient(RegisteredClientRepository registeredClientRepository, DemoProperties properties) {
        DemoProperties.Client client = properties.client();
        if (registeredClientRepository.findByClientId(client.clientId()) != null) {
            return;
        }
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(client.clientId())
                .clientName(client.clientName())
                // No client secret: this is a public client, which is exactly the case PKCE exists for.
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(properties.issuerUri() + "/login/oauth2/code/" + client.registrationId())
                .postLogoutRedirectUri(properties.issuerUri() + "/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .clientSettings(ClientSettings.builder()
                        // Reject any authorization request that arrives without a code_challenge.
                        .requireProofKey(true)
                        .requireAuthorizationConsent(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofHours(8))
                        .reuseRefreshTokens(false)
                        .build())
                .build();
        registeredClientRepository.save(registeredClient);
        log.info("Registered PKCE client [{}]", client.clientId());
    }
}
