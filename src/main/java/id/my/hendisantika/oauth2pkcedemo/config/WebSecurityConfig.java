package id.my.hendisantika.oauth2pkcedemo.config;

import id.my.hendisantika.oauth2pkcedemo.controller.LogoutDemoController;
import id.my.hendisantika.oauth2pkcedemo.security.PkceAuditingAuthorizationRequestRepository;
import id.my.hendisantika.oauth2pkcedemo.security.PushedAuthorizationRequestResolver;
import id.my.hendisantika.oauth2pkcedemo.service.PushedAuthorizationRequestService;
import id.my.hendisantika.oauth2pkcedemo.security.RestartOAuth2LoginFilter;
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
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
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
    public SecurityFilterChain defaultSecurityFilterChain(
            HttpSecurity http,
            DemoProperties properties,
            PushedAuthorizationRequestResolver authorizationRequestResolver) throws Exception {
        String authorizationRequestUri = "/oauth2/authorization/" + properties.client().registrationId();
        http
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/", "/error", "/css/**", "/js/**", "/favicon.ico").permitAll()
                        // A device has no browser session; the human signs in later, on their phone.
                        .requestMatchers("/device", "/device/**", "/activate", "/par").permitAll()
                        // The client publishes its keys here, and the authorization server
                        // fetches them unauthenticated.
                        .requestMatchers("/assertion", "/client-jwks.json", "/mtls", "/mtls-jwks.json", "/rar", "/jar", "/jar-jwks.json", "/fapi").permitAll()
                        // Drives its own authorization request, so it is reachable signed out and
                        // its redirect URI is its own rather than Spring's client callback.
                        .requestMatchers("/code-binding", "/code-binding/**").permitAll()
                        // The client's backend calls the backchannel endpoint; the demo page
                        // stands in for it and the user never visits either.
                        .requestMatchers("/ciba", "/ciba/poll", "/ciba/reset",
                                "/backchannel/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage(LOGIN_PAGE_URI)
                        .permitAll())
                .oauth2Login(oauth2 -> oauth2
                        .loginPage(authorizationRequestUri)
                        .authorizationEndpoint(endpoint -> endpoint
                                .authorizationRequestRepository(authorizationRequestRepository())
                                .authorizationRequestResolver(authorizationRequestResolver))
                        .defaultSuccessUrl("/dashboard", true))
                // Both formLogin and oauth2Login register a default entry point; pin it explicitly so
                // that hitting a protected page always starts the PKCE flow rather than the raw form.
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(authorizationRequestUri)))
                // Must run before the redirect filter builds a second authorization request on top
                // of an existing OAuth2 authentication. /code-binding/start is listed too: it builds
                // its authorization request by hand and would otherwise hit the same 500.
                .addFilterBefore(
                        new RestartOAuth2LoginFilter("/oauth2/authorization/**", "/code-binding/start"),
                        OAuth2AuthorizationRequestRedirectFilter.class)
                // Both stand in for calls the client's backend makes machine-to-machine, where no
                // browser session exists to carry a CSRF token. /ciba/poll also has to survive the
                // user signing in elsewhere in the same browser, which rotates the shared session's
                // token - an artefact of running client and phone in one browser, not of CIBA.
                .csrf(csrf -> csrf.ignoringRequestMatchers("/backchannel/**", "/ciba/poll"))
                .logout(logout -> logout
                        .logoutSuccessUrl("/")
                        .clearAuthentication(true)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID"));
        return http.build();
    }

    /**
     * Pushes the authorization request for the confidential registration before the browser is
     * redirected, so the front channel carries only a client id and an opaque handle.
     */
    @Bean
    public PushedAuthorizationRequestResolver pushedAuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository,
            PushedAuthorizationRequestService pushedAuthorizationRequestService,
            DemoProperties properties) {
        return new PushedAuthorizationRequestResolver(clientRegistrationRepository,
                pushedAuthorizationRequestService, properties.confidentialClient().registrationId());
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
