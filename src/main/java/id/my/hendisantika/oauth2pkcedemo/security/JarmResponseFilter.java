package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import lombok.extern.slf4j.Slf4j;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.http.MediaType;
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
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

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

    /** Signed, on the query string. {@code jwt} means this one for the authorization code flow. */
    public static final Set<String> QUERY_JWT_MODES = Set.of("jwt", "query.jwt");

    /** Signed, after the {@code #} - where a browser keeps it out of the request it sends. */
    public static final String FRAGMENT_JWT = "fragment.jwt";

    /** Signed, in the body of a form the browser posts - so it is in no URL at all. */
    public static final String FORM_POST_JWT = "form_post.jwt";

    /** Every mode this understands. Anything else is left to the authorization server. */
    public static final Set<String> JWT_MODES =
            Set.of("jwt", "query.jwt", FRAGMENT_JWT, FORM_POST_JWT);

    /**
     * The client's registered algorithm, as JARM names it. Spring Authorization Server has no
     * setting of its own for this, so it is carried as a custom one on the registration.
     */
    public static final String SIGNED_RESPONSE_ALG =
            "settings.client.authorization-signed-response-alg";

    /** JARM: set this and the signed response is encrypted to the client on top. */
    public static final String ENCRYPTED_RESPONSE_ALG =
            "settings.client.authorization-encrypted-response-alg";

    /** And this names the content encryption; JARM defaults it when only the algorithm is given. */
    public static final String ENCRYPTED_RESPONSE_ENC =
            "settings.client.authorization-encrypted-response-enc";

    /** JARM section 4.2: the default when a client asks for encryption and says nothing more. */
    public static final String DEFAULT_ENCRYPTION_METHOD = "A128CBC-HS256";

    /** What this server can actually sign with, which is what it has keys for. */
    public static final Set<String> SUPPORTED_ALGORITHMS = Set.of("RS256", "ES256");

    /** JARM: omitting the setting means RS256, so a client that says nothing still gets a signature. */
    public static final String DEFAULT_ALGORITHM = "RS256";

    /** Short: a response is redeemed immediately or not at all. */
    private static final Duration LIFETIME = Duration.ofMinutes(2);

    /** Carried as claims rather than as parameters, so they are not repeated in the JWT. */
    private static final Set<String> CLAIM_PARAMETERS = Set.of("iss");

    private final RequestMatcher authorizationEndpointMatcher;
    private final RegisteredClientRepository registeredClientRepository;
    private final JwtEncoder jwtEncoder;
    private final String issuerUri;

    /**
     * How a client's published key set is read. It is a seam because this demo's JARM client lives
     * in the same process as the server: a real deployment always goes over the network, and the
     * default here does too.
     */
    private Function<String, String> jwkSetFetcher = url ->
            RestClient.create().get().uri(url).retrieve().body(String.class);

    public JarmResponseFilter(String authorizationEndpointUri,
                              RegisteredClientRepository registeredClientRepository,
                              JwtEncoder jwtEncoder, String issuerUri) {
        this.authorizationEndpointMatcher =
                PathPatternRequestMatcher.withDefaults().matcher(authorizationEndpointUri);
        this.registeredClientRepository = registeredClientRepository;
        this.jwtEncoder = jwtEncoder;
        this.issuerUri = issuerUri;
    }

    /** @param jwkSetFetcher reads a client's published key set, given its URL */
    public JarmResponseFilter jwkSetFetcher(Function<String, String> jwkSetFetcher) {
        this.jwkSetFetcher = jwkSetFetcher;
        return this;
    }

    public static boolean wantsJwtResponse(HttpServletRequest request) {
        String mode = responseModeOf(request);
        return mode != null && JWT_MODES.contains(mode);
    }

    private static String responseModeOf(HttpServletRequest request) {
        String mode = request.getParameter(RESPONSE_MODE);
        return mode == null ? null : mode.trim();
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
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        filterChain.doFilter(request, new JarmRedirect(response, redirectUri, clientId,
                responseModeOf(request), algorithmFor(clientId)));
    }

    /** Wraps only the one thing that matters: where the authorization endpoint sends the browser. */
    private final class JarmRedirect extends HttpServletResponseWrapper {

        private final String redirectUri;
        private final String clientId;
        private final String responseMode;
        private final String algorithm;

        private JarmRedirect(HttpServletResponse response, String redirectUri, String clientId,
                             String responseMode, String algorithm) {
            super(response);
            this.redirectUri = redirectUri;
            this.clientId = clientId;
            this.responseMode = responseMode;
            this.algorithm = algorithm;
        }

        @Override
        public void sendRedirect(String location) throws IOException {
            if (location == null || !location.startsWith(redirectUri)) {
                // The login page, the consent screen, anywhere else: not a response to sign.
                super.sendRedirect(location);
                return;
            }
            Map<String, String> parameters = parametersOf(location);
            if (algorithm == null) {
                // The client asked to be answered in a way this server cannot produce. Handing it an
                // unsigned response instead would be the quiet failure the whole mode exists to
                // avoid, so it is told plainly - in the clear, because there is no other way left.
                log.debug("Cannot sign an authorization response for {}", clientId);
                super.sendRedirect(UriComponentsBuilder.fromUriString(redirectUri)
                        .queryParam(OAuth2ParameterNames.ERROR, "invalid_request")
                        .queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION,
                                "This server cannot sign an authorization response for this client")
                        .queryParam(OAuth2ParameterNames.STATE,
                                parameters.getOrDefault(OAuth2ParameterNames.STATE, ""))
                        .build().encode(StandardCharsets.UTF_8).toUriString());
                return;
            }
            String jwt = sign(parameters, clientId, algorithm);
            String encrypted = encryptIfRegistered(jwt, clientId);
            if (encrypted == null) {
                super.sendRedirect(UriComponentsBuilder.fromUriString(redirectUri)
                        .queryParam(OAuth2ParameterNames.ERROR, "invalid_request")
                        .queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION,
                                "This server cannot encrypt an authorization response for this client")
                        .queryParam(OAuth2ParameterNames.STATE,
                                parameters.getOrDefault(OAuth2ParameterNames.STATE, ""))
                        .build().encode(StandardCharsets.UTF_8).toUriString());
                return;
            }
            jwt = encrypted;
            log.debug("Delivering a {} authorization response as a signed JWT, by {}",
                    parameters.containsKey(OAuth2ParameterNames.ERROR) ? "failed" : "successful",
                    responseMode);

            if (FORM_POST_JWT.equals(responseMode)) {
                formPost(jwt);
                return;
            }
            if (FRAGMENT_JWT.equals(responseMode)) {
                // After the #, where a browser keeps it: the fragment is never sent to the server
                // the URI points at, so the response stays out of that server's logs entirely.
                super.sendRedirect(redirectUri + "#" + RESPONSE + "="
                        + URLEncoder.encode(jwt, StandardCharsets.UTF_8));
                return;
            }
            super.sendRedirect(UriComponentsBuilder.fromUriString(redirectUri)
                    .queryParam(RESPONSE, jwt)
                    .build().encode(StandardCharsets.UTF_8).toUriString());
        }

        /**
         * OAuth 2.0 Form Post Response Mode: a page whose only purpose is to submit itself, so the
         * response travels in a request body rather than in any URL. That matters for a JWT, which
         * is long enough to run into URL length limits, and which would otherwise sit in browser
         * history and in every log along the way.
         */
        private void formPost(String jwt) throws IOException {
            String html = """
                    <!DOCTYPE html>
                    <html><head><title>Submitting the response</title></head>
                    <body onload="document.forms[0].submit()">
                    <form method="post" action="%s">
                    <input type="hidden" name="%s" value="%s"/>
                    <noscript><button type="submit">Continue</button></noscript>
                    </form></body></html>"""
                    .formatted(escape(redirectUri), RESPONSE, escape(jwt));
            setStatus(HttpServletResponse.SC_OK);
            setContentType(MediaType.TEXT_HTML_VALUE);
            setCharacterEncoding(StandardCharsets.UTF_8);
            getWriter().write(html);
        }
    }

    /**
     * The response parameters become claims alongside the three the mode adds. A failed response is
     * signed exactly like a successful one: a client that cannot trust an error is no better off
     * than one that cannot trust a code.
     */
    private String sign(Map<String, String> parameters, String clientId, String algorithm) {
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
                JwsHeader.with(SignatureAlgorithm.from(algorithm)).build(), claims.build()))
                .getTokenValue();
    }

    /** Only the characters that could end the attribute; the values here are a URI and a JWT. */
    private static String escape(String value) {
        return value.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;");
    }

    /**
     * JARM section 4.2: when a client registers an encryption algorithm, the signed response becomes
     * the payload of a JWE addressed to it. The order matters and is not a preference - signing
     * first and encrypting second means the signature is over the response the client will read.
     * Encrypting first and signing the ciphertext would prove only that somebody signed an opaque
     * blob, which is no statement about its contents at all.
     *
     * @return the response to deliver, unchanged when no encryption was asked for, or {@code null}
     * when the client asked for one this server cannot produce
     */
    private String encryptIfRegistered(String signedJwt, String clientId) {
        RegisteredClient client = clientId == null ? null
                : this.registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            return signedJwt;
        }
        Object algorithm = client.getClientSettings().getSetting(ENCRYPTED_RESPONSE_ALG);
        if (algorithm == null) {
            return signedJwt;
        }
        Object method = client.getClientSettings().getSetting(ENCRYPTED_RESPONSE_ENC);
        String jwkSetUrl = client.getClientSettings().getJwkSetUrl();
        if (jwkSetUrl == null) {
            log.debug("{} asked for encrypted responses and publishes no keys", clientId);
            return null;
        }
        try {
            RSAKey key = encryptionKeyOf(jwkSetUrl);
            JWEObject encrypted = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.parse(String.valueOf(algorithm)),
                            EncryptionMethod.parse(method == null
                                    ? DEFAULT_ENCRYPTION_METHOD : String.valueOf(method)))
                            .keyID(key.getKeyID())
                            // RFC 7519 section 5.2: a nested JWT says so, so the client knows to
                            // verify a signature once it has decrypted rather than read claims.
                            .contentType("JWT")
                            .build(),
                    new Payload(signedJwt));
            encrypted.encrypt(new RSAEncrypter(key));
            return encrypted.serialize();
        } catch (Exception ex) {
            log.debug("Unable to encrypt a response for {}: {}", clientId, ex.getMessage());
            return null;
        }
    }

    /** The first key in the client's published set that can be encrypted to. */
    private RSAKey encryptionKeyOf(String jwkSetUrl) throws Exception {
        String jwks = this.jwkSetFetcher.apply(jwkSetUrl);
        for (JWK jwk : JWKSet.parse(jwks).getKeys()) {
            if (jwk instanceof RSAKey rsaKey && KeyUse.SIGNATURE != jwk.getKeyUse()) {
                return rsaKey;
            }
        }
        throw new IllegalStateException("No usable encryption key at " + jwkSetUrl);
    }

    /**
     * JARM leaves the algorithm to the registration and defaults it to RS256 when the client says
     * nothing. It also forbids {@code none} outright: a response mode whose entire purpose is a
     * signature cannot be satisfied by an unsigned JWT, and a server that accepted the value would be
     * promising something it was not doing.
     *
     * @return the algorithm to sign with, or {@code null} when this server cannot honour the setting
     */
    public String algorithmFor(String clientId) {
        RegisteredClient client = clientId == null ? null
                : this.registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            return null;
        }
        Object configured = client.getClientSettings().getSetting(SIGNED_RESPONSE_ALG);
        String algorithm = configured == null ? DEFAULT_ALGORITHM : String.valueOf(configured);
        return SUPPORTED_ALGORITHMS.contains(algorithm) ? algorithm : null;
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
