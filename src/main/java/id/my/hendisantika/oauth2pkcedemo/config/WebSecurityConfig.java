package id.my.hendisantika.oauth2pkcedemo.config;

import id.my.hendisantika.oauth2pkcedemo.controller.CheckSessionIframeController;
import id.my.hendisantika.oauth2pkcedemo.controller.JarmController;
import id.my.hendisantika.oauth2pkcedemo.controller.LogoutDemoController;
import id.my.hendisantika.oauth2pkcedemo.security.PkceAuditingAuthorizationRequestRepository;
import id.my.hendisantika.oauth2pkcedemo.security.PushedAuthorizationRequestResolver;
import id.my.hendisantika.oauth2pkcedemo.service.PushedAuthorizationRequestService;
import id.my.hendisantika.oauth2pkcedemo.security.RestartOAuth2LoginFilter;
import id.my.hendisantika.oauth2pkcedemo.security.RevokingLogoutHandler;
import id.my.hendisantika.oauth2pkcedemo.service.TokenAdminService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.Customizer;
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
            PushedAuthorizationRequestResolver authorizationRequestResolver,
            RevokingLogoutHandler revokingLogoutHandler) throws Exception {
        String authorizationRequestUri = "/oauth2/authorization/" + properties.client().registrationId();
        http
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/", "/error", "/css/**", "/js/**", "/favicon.ico").permitAll()
                        // A device has no browser session; the human signs in later, on their phone.
                        .requestMatchers("/device", "/device/**", "/activate", "/par").permitAll()
                        // Stands in for a device, which has no session here either.
                        .requestMatchers("/refresh-binding", "/refresh-binding/**").permitAll()
                        .requestMatchers("/mtls-refresh", "/mtls-refresh/**").permitAll()
                        // Its probe brings its own session; the page itself shows nobody's data.
                        .requestMatchers("/silent-auth", "/silent-auth/**").permitAll()
                        // Same shape: the probe brings its own session and its own client.
                        .requestMatchers("/request-uri", "/request-uri/**").permitAll()
                        .requestMatchers("/rar-enforcement", "/rar-enforcement/**").permitAll()
                        .requestMatchers("/dpop-nonce", "/dpop-nonce/**").permitAll()
                        .requestMatchers("/introspection-jwt", "/introspection-jwt/**").permitAll()
                        .requestMatchers("/jarm", "/jarm/**").permitAll()
                        .requestMatchers("/jarm-alg", "/jarm-alg/**").permitAll()
                        .requestMatchers("/jarm-enc", "/jarm-enc/**").permitAll()
                        .requestMatchers("/jarm-enc-method", "/jarm-enc-method/**").permitAll()
                        .requestMatchers("/jar-enc", "/jar-enc/**").permitAll()
                        .requestMatchers("/jar-alg", "/jar-alg/**").permitAll()
                        .requestMatchers("/jar-enc-alg", "/jar-enc-alg/**").permitAll()
                        .requestMatchers("/jar-enc-method", "/jar-enc-method/**").permitAll()
                        .requestMatchers("/jar-none", "/jar-none/**").permitAll()
                        .requestMatchers("/jar-required", "/jar-required/**").permitAll()
                        .requestMatchers("/jar-client-required", "/jar-client-required/**").permitAll()
                        .requestMatchers("/par-required", "/par-required/**").permitAll()
                        .requestMatchers("/par-server-required", "/par-server-required/**").permitAll()
                        .requestMatchers("/request-uri-metadata", "/request-uri-metadata/**").permitAll()
                        .requestMatchers("/request-uri-registration", "/request-uri-registration/**").permitAll()
                        // RFC 9101 section 5.2.1: the client's own hosting, which the server fetches.
                        .requestMatchers("/hosted/**").permitAll()
                        // The client publishes its keys here, and the authorization server
                        // fetches them unauthenticated.
                        .requestMatchers("/assertion", "/client-jwks.json", "/mtls", "/mtls-jwks.json", "/rar", "/jar", "/jar-jwks.json", "/jarm-client-jwks.json", "/fapi").permitAll()
                        // Drives its own authorization request, so it is reachable signed out and
                        // its redirect URI is its own rather than Spring's client callback.
                        .requestMatchers("/code-binding", "/code-binding/**").permitAll()
                        // Both the client and the rogue authorization server it was pointed at, so
                        // a run can be followed from either side without signing in first.
                        .requestMatchers("/mixup", "/mixup/**").permitAll()
                        // Reads the published documents back over HTTP, which anyone may do.
                        .requestMatchers("/metadata").permitAll()
                        // Registration is machine to machine from end to end; no session is
                        // involved in any of it.
                        .requestMatchers("/dynamic-registration", "/dynamic-registration/**").permitAll()
                        // A run ends signed out, and the result has to be readable afterwards.
                        .requestMatchers("/logout-revocation").permitAll()
                        // Same reason: a run ends with the session it was about already gone.
                        .requestMatchers("/backchannel-logout").permitAll()
                        // The demo page, and the client endpoint the iframes on it load - which has
                        // to be reachable with or without a session, since not having one is half of
                        // what the page is about.
                        .requestMatchers("/frontchannel-logout", "/frontchannel/logout/**").permitAll()
                        // The page works signed out too - it just always answers "changed".
                        .requestMatchers("/session-management", "/session-management/**").permitAll()
                        // The provider's iframe is a page, loaded by a browser that may have no
                        // session here at all - which is one of the answers it exists to give.
                        .requestMatchers(CheckSessionIframeController.URI).permitAll()
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
                // OpenID Connect Back-Channel Logout, the receiving half. Spring Security has it;
                // it listens on /logout/connect/back-channel/{registrationId} and needs nothing
                // more than switching on. Spring Authorization Server has no sending half at all.
                .oidcLogout(oidc -> oidc.backChannel(Customizer.withDefaults()))
                // Both formLogin and oauth2Login register a default entry point; pin it explicitly so
                // that hitting a protected page always starts the PKCE flow rather than the raw form.
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(authorizationRequestUri)))
                // Must run before the redirect filter builds a second authorization request on top
                // of an existing OAuth2 authentication. /code-binding/start is listed too: it builds
                // its authorization request by hand and would otherwise hit the same 500.
                .addFilterBefore(
                        new RestartOAuth2LoginFilter("/oauth2/authorization/**", "/code-binding/start",
                                "/mixup/start"),
                        OAuth2AuthorizationRequestRedirectFilter.class)
                // Both stand in for calls the client's backend makes machine-to-machine, where no
                // browser session exists to carry a CSRF token. /ciba/poll also has to survive the
                // user signing in elsewhere in the same browser, which rotates the shared session's
                // token - an artefact of running client and phone in one browser, not of CIBA.
                .csrf(csrf -> csrf.ignoringRequestMatchers("/backchannel/**", "/ciba/poll",
                        "/mixup/attacker/token",
                        // A form_post.jwt response is submitted by a page the authorization server
                        // wrote, carrying no token of this application's - which is exactly the
                        // shape of a response arriving from a server elsewhere.
                        JarmController.CALLBACK_URI))
                // The front-channel logout page embeds the client's own logout endpoint in
                // iframes, and the default DENY would stop the browser loading them. In a real
                // deployment the client and the server are different origins and this is the
                // client's decision to make, not the server's.
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))
                .logout(logout -> logout
                        // Signing out of the client says nothing to the authorization server about
                        // the tokens it issued. This is what says it.
                        .addLogoutHandler(revokingLogoutHandler)
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

    /**
     * Revokes the session's tokens as part of logging out. Nothing in either logout does this on its
     * own, and without it signing out leaves a usable access token behind.
     */
    @Bean
    public RevokingLogoutHandler revokingLogoutHandler(OAuth2AuthorizedClientService authorizedClientService,
                                                       TokenAdminService tokenAdminService) {
        return new RevokingLogoutHandler(authorizedClientService, tokenAdminService);
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
