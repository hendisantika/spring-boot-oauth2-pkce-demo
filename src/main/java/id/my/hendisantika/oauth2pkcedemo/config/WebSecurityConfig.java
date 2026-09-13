package id.my.hendisantika.oauth2pkcedemo.config;

import id.my.hendisantika.oauth2pkcedemo.controller.LogoutDemoController;
import id.my.hendisantika.oauth2pkcedemo.security.PkceAuditingAuthorizationRequestRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 12.56
 */
@Configuration(proxyBeanMethods = false)
public class WebSecurityConfig {

    public static final String LOGIN_PAGE_URI = "/login";

    /**
     * Everything the authorization server chain did not claim: the landing page, the login form
     * that the authorization server redirects to, the consent screen, and the demo pages that are
     * protected by an OAuth2 login against this same app.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          DemoProperties properties) throws Exception {
        String authorizationRequestUri = "/oauth2/authorization/" + properties.client().registrationId();
        http
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/", "/error", "/css/**", "/js/**", "/favicon.ico").permitAll()
                        // A device has no browser session; the human signs in later, on their phone.
                        .requestMatchers("/device", "/device/**", "/activate").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage(LOGIN_PAGE_URI)
                        .permitAll())
                .oauth2Login(oauth2 -> oauth2
                        .loginPage(authorizationRequestUri)
                        .authorizationEndpoint(endpoint -> endpoint
                                .authorizationRequestRepository(authorizationRequestRepository()))
                        .defaultSuccessUrl("/dashboard", true))
                // Both formLogin and oauth2Login register a default entry point; pin it explicitly so
                // that hitting a protected page always starts the PKCE flow rather than the raw form.
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(authorizationRequestUri)))
                .logout(logout -> logout
                        .logoutSuccessUrl("/")
                        .clearAuthentication(true)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID"));
        return http.build();
    }

    @Bean
    public PkceAuditingAuthorizationRequestRepository authorizationRequestRepository() {
        return new PkceAuditingAuthorizationRequestRepository();
    }

    /**
     * Built in code rather than through {@code spring.security.oauth2.client.*} because a
     * properties-based registration with an {@code issuer-uri} performs OIDC discovery while the
     * context is still starting - and the provider being discovered is this very application.
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(DemoProperties properties) {
        return new InMemoryClientRegistrationRepository(
                registrationFor(properties, properties.client()),
                registrationFor(properties, properties.confidentialClient()));
    }

    private static ClientRegistration registrationFor(DemoProperties properties, DemoProperties.Client client) {
        String issuer = properties.issuerUri();
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(client.registrationId())
                .clientId(client.clientId())
                .clientName(client.clientName())
                // Force PKCE for both clients. Spring only applies it automatically to public ones.
                .clientSettings(ClientRegistration.ClientSettings.builder().requireProofKey(true).build())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(client.scopes())
                .issuerUri(issuer)
                .authorizationUri(issuer + "/oauth2/authorize")
                .tokenUri(issuer + "/oauth2/token")
                .jwkSetUri(issuer + "/oauth2/jwks")
                .userInfoUri(issuer + "/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                // Not part of ClientRegistration's typed surface, but RP-initiated logout needs it;
                // discovery would normally supply it.
                .providerConfigurationMetadata(Map.of(
                        LogoutDemoController.END_SESSION_ENDPOINT, issuer + "/connect/logout"));

        if (client.isPublic()) {
            // No secret to leak, so the authorization code is bound to the caller by PKCE alone.
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        } else {
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientSecret(client.clientSecret());
        }
        return builder.build();
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            JdbcOperations jdbcOperations, ClientRegistrationRepository clientRegistrationRepository) {
        return new JdbcOAuth2AuthorizedClientService(jdbcOperations, clientRegistrationRepository);
    }

    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository(
            OAuth2AuthorizedClientService authorizedClientService) {
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
