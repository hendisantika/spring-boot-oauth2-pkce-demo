package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 11.30
 */
@Slf4j
public final class JarmResponseFilter extends OncePerRequestFilter {

    public static final String RESPONSE_MODE = "response_mode";
    public static final String RESPONSE = "response";

    /** The modes that mean "signed, delivered on the query string", which is all the code flow needs. */
    public static final Set<String> QUERY_JWT_MODES = Set.of("jwt", "query.jwt");

    /** Short: a response is redeemed immediately or not at all. */
    private static final Duration LIFETIME = Duration.ofMinutes(2);

    /** Carried as claims rather than as parameters, so they are not repeated in the JWT. */
    private static final Set<String> CLAIM_PARAMETERS = Set.of("iss");

    private final RequestMatcher authorizationEndpointMatcher;
    private final RegisteredClientRepository registeredClientRepository;
    private final JwtEncoder jwtEncoder;
    private final String issuerUri;

    public JarmResponseFilter(String authorizationEndpointUri,
                              RegisteredClientRepository registeredClientRepository,
                              JwtEncoder jwtEncoder, String issuerUri) {
        this.authorizationEndpointMatcher =
                PathPatternRequestMatcher.withDefaults().matcher(authorizationEndpointUri);
        this.registeredClientRepository = registeredClientRepository;
        this.jwtEncoder = jwtEncoder;
        this.issuerUri = issuerUri;
    }

    public static boolean wantsJwtResponse(HttpServletRequest request) {
        String mode = request.getParameter(RESPONSE_MODE);
        return mode != null && QUERY_JWT_MODES.contains(mode.trim());
    }

    /**
     * JWT Secured Authorization Response Mode. An ordinary authorization response is a handful of
     * loose query parameters: nothing says who sent them, nothing says who they are for, and
     * anything that can reach the redirect URI can change them. JARM puts the whole response in one
     * signed JWT instead - {@code iss}, {@code aud}, {@code exp} and the parameters together - so
     * the client can tell where its answer came from and that it arrived as written.
     * <p>
     * Spring Authorization Server does not read {@code response_mode} at all: the string appears
     * nowhere in it. A client asking for a signed response gets loose parameters and no indication
     * that it asked for anything, which is the worst of the three possible outcomes. This filter
     * wraps the response and repackages the redirect the authorization endpoint was about to send.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!this.authorizationEndpointMatcher.matches(request) || !wantsJwtResponse(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String redirectUri = registeredRedirectUri(request);
        if (redirectUri == null) {
            // Nothing to protect: the authorization server will refuse this on its own terms, and
            // its refusal should not be dressed up as a signed answer.
            filterChain.doFilter(request, response);
            return;
        }
        filterChain.doFilter(request, new JarmRedirect(response, redirectUri,
                request.getParameter(OAuth2ParameterNames.CLIENT_ID)));
    }

    /** Wraps only the one thing that matters: where the authorization endpoint sends the browser. */
    private final class JarmRedirect extends HttpServletResponseWrapper {

        private final String redirectUri;
        private final String clientId;

        private JarmRedirect(HttpServletResponse response, String redirectUri, String clientId) {
            super(response);
            this.redirectUri = redirectUri;
            this.clientId = clientId;
        }

        @Override
        public void sendRedirect(String location) throws IOException {
            if (location == null || !location.startsWith(redirectUri)) {
                // The login page, the consent screen, anywhere else: not a response to sign.
                super.sendRedirect(location);
                return;
            }
            Map<String, String> parameters = parametersOf(location);
            String jwt = sign(parameters, clientId);
            log.debug("Delivering a {} authorization response as a signed JWT",
                    parameters.containsKey(OAuth2ParameterNames.ERROR) ? "failed" : "successful");
            super.sendRedirect(UriComponentsBuilder.fromUriString(redirectUri)
                    .queryParam(RESPONSE, jwt)
                    .build().encode(StandardCharsets.UTF_8).toUriString());
        }
    }

    /**
     * The response parameters become claims alongside the three the mode adds. A failed response is
     * signed exactly like a successful one: a client that cannot trust an error is no better off
     * than one that cannot trust a code.
     */
    private String sign(Map<String, String> parameters, String clientId) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(issuerUri)
                // Addressed to the client that asked, so a response delivered anywhere else says
                // whose it was and is of no use to whoever received it.
                .audience(List.of(clientId))
                .issuedAt(now)
                .expiresAt(now.plus(LIFETIME));
        parameters.forEach((name, value) -> {
            if (!CLAIM_PARAMETERS.contains(name)) {
                claims.claim(name, value);
            }
        });
        return jwtEncoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).build(), claims.build())).getTokenValue();
    }

    /** The redirect URI the client registered, which is the only place a response may be sent. */
    private String registeredRedirectUri(HttpServletRequest request) {
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);
        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(redirectUri)) {
            return null;
        }
        RegisteredClient client = this.registeredClientRepository.findByClientId(clientId);
        return client != null && client.getRedirectUris().contains(redirectUri) ? redirectUri : null;
    }

    /** Pulls the loose parameters back off the redirect the server was about to send. */
    private static Map<String, String> parametersOf(String location) {
        Map<String, String> parameters = new LinkedHashMap<>();
        int query = location.indexOf('?');
        if (query < 0) {
            return parameters;
        }
        for (String pair : List.of(location.substring(query + 1).split("&"))) {
            int equals = pair.indexOf('=');
            if (equals > 0) {
                parameters.put(URLDecoder.decode(pair.substring(0, equals), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8));
            }
        }
        return parameters;
    }
}
