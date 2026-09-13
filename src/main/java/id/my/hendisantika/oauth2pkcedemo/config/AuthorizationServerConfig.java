package id.my.hendisantika.oauth2pkcedemo.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import id.my.hendisantika.oauth2pkcedemo.repository.UserRepository;
import id.my.hendisantika.oauth2pkcedemo.security.DeviceClientAuthenticationConverter;
import id.my.hendisantika.oauth2pkcedemo.security.DpopBoundAuthorizationCodeFilter;
import id.my.hendisantika.oauth2pkcedemo.security.IssuerIdentifierResponseHandler;
import id.my.hendisantika.oauth2pkcedemo.security.LogoutTokenFactory;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import id.my.hendisantika.oauth2pkcedemo.security.AuthenticationContextLevel;
import org.springframework.security.core.Authentication;
import id.my.hendisantika.oauth2pkcedemo.controller.JarJwkSetController;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.CibaAuthenticationConverter;
import id.my.hendisantika.oauth2pkcedemo.security.StepUpRequiredFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import id.my.hendisantika.oauth2pkcedemo.security.CibaAuthenticationProvider;
import id.my.hendisantika.oauth2pkcedemo.service.CibaService;
import org.springframework.security.core.userdetails.UserDetailsService;
import id.my.hendisantika.oauth2pkcedemo.security.DeviceClientAuthenticationProvider;
import id.my.hendisantika.oauth2pkcedemo.security.RichAuthorizationDetail;
import id.my.hendisantika.oauth2pkcedemo.security.RichAuthorizationRequestValidator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

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
public class AuthorizationServerConfig {

    /**
     * OpenID Connect Back-Channel Logout section 2.1. Spring Authorization Server already puts this
     * on ID tokens, from the session registry, so nothing here has to add it - a logout token just
     * has to name the same value.
     */
    public static final String SESSION_ID = "sid";

    public static final String CONSENT_PAGE_URI = "/oauth2/consent";
    public static final String ACTIVATION_PAGE_URI = "/activate";

    /**
     * Owns every authorization server endpoint (/oauth2/authorize, /oauth2/token, /oauth2/jwks,
     * /userinfo, /.well-known/**). Anything it does not match falls through to
     * {@link WebSecurityConfig}, which is where the login form and the demo pages live.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            RegisteredClientRepository registeredClientRepository,
            AuthorizationServerSettings authorizationServerSettings,
            CibaService cibaService,
            UserDetailsService userDetailsService,
            OAuth2AuthorizationService authorizationService,
            JWKSource<SecurityContext> jwkSource,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer,
            JarRequestSigner jarRequestSigner,
            IssuerIdentifierResponseHandler issuerIdentifierResponseHandler,
            ServerMetadataCustomizer serverMetadataCustomizer,
            DemoProperties properties) throws Exception {
        // A generator of its own rather than a shared bean. Supplying an OAuth2TokenGenerator bean
        // replaces the one Spring Authorization Server assembles internally, and that one carries
        // DPoP handling this reimplementation would silently drop - tokens came back as Bearer with
        // no cnf claim. CIBA never involves DPoP, so a plain JWT generator is right here.
        JwtGenerator cibaTokenGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        cibaTokenGenerator.setJwtCustomizer(jwtCustomizer);
        CibaAuthenticationProvider cibaAuthenticationProvider = new CibaAuthenticationProvider(
                cibaService, userDetailsService, authorizationService, cibaTokenGenerator);
        OAuth2AuthorizationServerConfigurer authorizationServer = new OAuth2AuthorizationServerConfigurer();
        http
                .securityMatcher(authorizationServer.getEndpointsMatcher())
                .with(authorizationServer, server -> server
                        .authorizationEndpoint(endpoint -> endpoint
                                .consentPage(CONSENT_PAGE_URI)
                                // Nothing in Spring Authorization Server validates RFC 9396
                                // authorization_details, so this inspects the request before it is
                                // stored and consented to.
                                .authorizationRequestConverter(new RichAuthorizationRequestValidator())
                                // RFC 9207. The built-in handlers send code and state and stop
                                // there, leaving a client that talks to several authorization
                                // servers unable to tell which one answered.
                                .authorizationResponseHandler(issuerIdentifierResponseHandler)
                                .errorResponseHandler(issuerIdentifierResponseHandler))
                        // RFC 9126. Off by default, and absent from the discovery document until it
                        // is switched on here.
                        .pushedAuthorizationRequestEndpoint(endpoint -> endpoint
                                // A pushed request carries authorization_details in the push, not in
                                // the later redirect, so this is where they have to be checked.
                                .pushedAuthorizationRequestConverter(new RichAuthorizationRequestValidator()))
                        // Lets a public client identify itself with client_id alone at the device
                        // authorization endpoint, which nothing built in covers.
                        .clientAuthentication(clientAuthentication -> clientAuthentication
                                .authenticationConverter(new DeviceClientAuthenticationConverter(
                                        authorizationServerSettings.getDeviceAuthorizationEndpoint(),
                                        authorizationServerSettings.getTokenEndpoint()))
                                .authenticationProvider(new DeviceClientAuthenticationProvider(
                                        registeredClientRepository)))
                        // RFC 8628: the device is told to send its user here, and the code the user
                        // types lands back on the same consent screen as the browser flow.
                        .deviceAuthorizationEndpoint(endpoint -> endpoint.verificationUri(ACTIVATION_PAGE_URI))
                        .deviceVerificationEndpoint(endpoint -> endpoint
                                .consentPage(CONSENT_PAGE_URI)
                                .errorResponseHandler(deviceVerificationErrorHandler()))
                        // CIBA is not a grant Spring Authorization Server knows, so the token
                        // endpoint is taught to recognise and handle it.
                        .tokenEndpoint(endpoint -> endpoint
                                .accessTokenRequestConverter(new CibaAuthenticationConverter())
                                .authenticationProvider(cibaAuthenticationProvider))
                        // RFC 8414. Served by default, but describing only what Spring
                        // Authorization Server itself knows about.
                        .authorizationServerMetadataEndpoint(endpoint -> endpoint
                                .authorizationServerMetadataCustomizer(serverMetadataCustomizer::customize))
                        .oidc(oidc -> oidc
                                // The same additions again: one server, two documents, and no
                                // reason for them to disagree.
                                .providerConfigurationEndpoint(endpoint -> endpoint
                                        .providerConfigurationCustomizer(serverMetadataCustomizer::customize))
                                // RFC 7591 by way of OpenID Connect Registration. Off by default,
                                // and absent from both metadata documents until it is switched on.
                                .clientRegistrationEndpoint(Customizer.withDefaults())))
                .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServer.getEndpointsMatcher()))
                // A browser hitting /oauth2/authorize while signed out is sent to the form login,
                // which is what turns this into an interactive login flow.
                .exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint(WebSecurityConfig.LOGIN_PAGE_URI),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                // Anchored to SecurityContextHolderFilter: the SecurityContext is loaded by then,
                // and the authorization server's own endpoint filters run later. Anchoring to
                // OAuth2AuthorizationEndpointFilter is not possible - the configurer adds it outside
                // Spring Security's registered filter order.
                .addFilterAfter(
                        new StepUpRequiredFilter(authorizationServerSettings.getAuthorizationEndpoint()),
                        SecurityContextHolderFilter.class)
                // Expands a signed request object before anything reads the request parameters, so
                // acr_values and everything else are taken from the JWT rather than the query string.
                .addFilterBefore(
                        new JwtSecuredAuthorizationRequestFilter(
                                authorizationServerSettings.getAuthorizationEndpoint(),
                                () -> parseJwkSet(jarRequestSigner.publicJwkSetJson()),
                                properties.issuerUri()),
                        StepUpRequiredFilter.class)
                // RFC 9449 section 10. Runs ahead of the token endpoint so that a request which
                // cannot prove possession of the key the code was bound to is turned away before
                // the code is spent.
                .addFilterAfter(
                        new DpopBoundAuthorizationCodeFilter(
                                authorizationServerSettings.getTokenEndpoint(), authorizationService),
                        SecurityContextHolderFilter.class);
        return http.build();
    }

    /**
     * There is no redirect URI to bounce an error back to in the device flow, so the default
     * response is a raw JSON 400 - which is fine for the device but not for the person holding the
     * phone. Deny the request, or mistype a code, and this sends them back to the activation page
     * with something readable.
     */
    private static AuthenticationFailureHandler deviceVerificationErrorHandler() {
        return (request, response, exception) -> {
            String errorCode = exception instanceof OAuth2AuthenticationException oauth2Exception
                    ? oauth2Exception.getError().getErrorCode()
                    : OAuth2ErrorCodes.INVALID_REQUEST;
            response.sendRedirect(request.getContextPath() + ACTIVATION_PAGE_URI
                    + "?error=" + URLEncoder.encode(errorCode, StandardCharsets.UTF_8));
        };
    }

    private static com.nimbusds.jose.jwk.JWKSet parseJwkSet(String json) {
        try {
            return com.nimbusds.jose.jwk.JWKSet.parse(json);
        } catch (java.text.ParseException ex) {
            throw new IllegalStateException("Unable to read the request object signing keys", ex);
        }
    }

    /**
     * A bean rather than an inline handler, so that anything asking whether this server identifies
     * its authorization responses - the FAPI compliance page does - is asking about the object that
     * actually sends them.
     */
    @Bean
    public IssuerIdentifierResponseHandler issuerIdentifierResponseHandler(DemoProperties properties) {
        return new IssuerIdentifierResponseHandler(properties.issuerUri());
    }

    /**
     * Adds what this application supports but Spring Authorization Server has no way to know about,
     * to both metadata documents.
     */
    @Bean
    public ServerMetadataCustomizer serverMetadataCustomizer(AuthorizationServerSettings settings,
                                                             DemoProperties properties) {
        return new ServerMetadataCustomizer(settings, properties);
    }

    /**
     * Mints the logout tokens the back-channel demo sends, with the same key everything else here
     * is signed with - a client verifies one by fetching the issuer's JWK Set.
     */
    @Bean
    public LogoutTokenFactory logoutTokenFactory(JWKSource<SecurityContext> jwkSource) {
        return new LogoutTokenFactory(jwkSource);
    }

    /** Generated per boot, like the server's own signing key. */
    @Bean
    public JarRequestSigner jarRequestSigner() {
        return JarRequestSigner.generate();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(DemoProperties properties) {
        return AuthorizationServerSettings.builder()
                .issuer(properties.issuerUri())
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations) {
        return new JdbcRegisteredClientRepository(jdbcOperations);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations,
                                                           RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository);
    }

    /**
     * Copies the authenticated user's authorities and profile onto the issued tokens, so the
     * dashboard and the /userinfo endpoint have something to show beyond the subject.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(UserRepository userRepository) {
        return context -> {
            if (!(context.getPrincipal().getPrincipal() instanceof UserDetails user)) {
                return;
            }
            // Must be an ArrayList: the JDBC authorization store serialises claims with Jackson's
            // polymorphic typing, whose allow-list rejects the immutable list Stream.toList() returns.
            context.getClaims().claim("authorities", user.getAuthorities().stream()
                    .map(Object::toString)
                    .collect(Collectors.toCollection(ArrayList::new)));

            // OpenID Connect Core section 2: say how strongly the user authenticated, and by what
            // means. A resource server can then insist on a level rather than trusting that a token
            // exists at all.
            Authentication principal = context.getPrincipal();
            context.getClaims().claim("acr", AuthenticationContextLevel.acrOf(principal));
            context.getClaims().claim("amr", new ArrayList<>(AuthenticationContextLevel.amrOf(principal)));

            // RFC 9396 section 7: echo the approved authorization details into the token, so a
            // resource server sees what was actually granted rather than only a scope name.
            richAuthorizationDetails(context).ifPresent(details ->
                    context.getClaims().claim(RichAuthorizationRequestValidator.AUTHORIZATION_DETAILS, details));

            userRepository.findByUsername(user.getUsername()).ifPresent(account -> {
                // Only release what the user actually consented to.
                if (context.getAuthorizedScopes().contains(OidcScopes.PROFILE)) {
                    context.getClaims().claim(StandardClaimNames.PREFERRED_USERNAME, account.getUsername());
                    context.getClaims().claim(StandardClaimNames.NAME, account.getFullName());
                }
                if (context.getAuthorizedScopes().contains(OidcScopes.EMAIL)) {
                    context.getClaims().claim(StandardClaimNames.EMAIL, account.getEmail());
                    context.getClaims().claim(StandardClaimNames.EMAIL_VERIFIED, true);
                }
            });
        };
    }

    /**
     * Digs the authorization_details out of the stored authorization request. They are kept as a raw
     * JSON string, so they are parsed back into a list for the claim.
     */
    private static Optional<Object> richAuthorizationDetails(JwtEncodingContext context) {
        OAuth2Authorization authorization = context.getAuthorization();
        if (authorization == null) {
            return Optional.empty();
        }
        OAuth2AuthorizationRequest authorizationRequest =
                authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
        if (authorizationRequest == null) {
            return Optional.empty();
        }
        Object raw = authorizationRequest.getAdditionalParameters()
                .get(RichAuthorizationRequestValidator.AUTHORIZATION_DETAILS);
        if (raw == null) {
            return Optional.empty();
        }
        try {
            // An ArrayList, because the JDBC store's Jackson allow-list rejects immutable lists.
            return Optional.of(new ArrayList<>(
                    RichAuthorizationDetail.parse(String.valueOf(raw)).stream()
                            .map(RichAuthorizationDetail::asClaim)
                            .toList()));
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    /**
     * Generates a fresh RSA key on every boot. Good enough for a demo - a real deployment keeps a
     * stable key so that tokens survive a restart.
     */
    @Bean
    @ConditionalOnMissingBean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
                .jwtDecoder(jwkSource);
    }

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to generate the RSA key pair for token signing", ex);
        }
    }
}
