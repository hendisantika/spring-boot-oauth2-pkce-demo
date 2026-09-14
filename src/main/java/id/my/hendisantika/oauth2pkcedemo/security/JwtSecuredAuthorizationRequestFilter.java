package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.function.Supplier;
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
 * Date: 13/09/26
 * Time: 17.15
 */
@Slf4j
public final class JwtSecuredAuthorizationRequestFilter extends OncePerRequestFilter {

    public static final String REQUEST = "request";

    /** RFC 9101 section 10.8. */
    public static final String REQUEST_OBJECT_TYPE = "oauth-authz-req+jwt";

    /**
     * RFC 9101 section 10.1: the algorithm a client says it will sign request objects with. Spring
     * Authorization Server has no setting for it, so it travels as a custom one on the registration.
     */
    public static final String SIGNING_ALG_SETTING = "settings.client.request-object-signing-alg";

    /** What a client is taken to have registered when it registered nothing. */
    public static final String DEFAULT_SIGNING_ALG = "RS256";

    /** The algorithms this server will check a request object against. */
    public static final Set<String> SUPPORTED_SIGNING_ALGS = Set.of("RS256", "PS256");

    /**
     * OpenID Connect Dynamic Client Registration: the JWE {@code alg} a client declares it may
     * encrypt request objects with. Spring Authorization Server has no setting for it either.
     */
    public static final String ENCRYPTION_ALG_SETTING = "settings.client.request-object-encryption-alg";

    /** What a client is taken to have registered when it registered nothing. */
    public static final String DEFAULT_ENCRYPTION_ALG = "RSA-OAEP-256";

    /** The key-management algorithms this server will unwrap a request object with. */
    public static final Set<String> SUPPORTED_ENCRYPTION_ALGS =
            Set.of("RSA-OAEP-256", "RSA-OAEP-512");

    /**
     * OpenID Connect Dynamic Client Registration: the JWE {@code enc} a client declares it may
     * encrypt request objects with. The other half of the pair, and registered the same way.
     */
    public static final String ENCRYPTION_ENC_SETTING = "settings.client.request-object-encryption-enc";

    /**
     * The registration spec's own default rather than one invented here: "if
     * request_object_encryption_alg is specified, the default request_object_encryption_enc value is
     * A128CBC-HS256".
     */
    public static final String DEFAULT_ENCRYPTION_ENC = "A128CBC-HS256";

    /** The content encryption methods this server will decrypt a request object with. */
    public static final Set<String> SUPPORTED_ENCRYPTION_METHODS =
            Set.of("A128CBC-HS256", "A256GCM");

    /** Claims that carry the JWT's own identity rather than authorization request parameters. */
    private static final List<String> JWT_CLAIMS = List.of("iss", "aud", "exp", "iat", "nbf", "jti");

    private final RequestMatcher authorizationEndpointMatcher;
    private final Supplier<JWKSet> clientKeys;

    /** The private half of the key this server publishes for clients to encrypt requests to. */
    private final RSAKey decryptionKey;

    /** Where the registered signing algorithm is read from. */
    private final RegisteredClientRepository registeredClients;

    private final String issuerUri;

    /**
     * @param clientKeys the client's public keys. A deployment fetches these from the
     *                   {@code jwkSetUrl} on the client's registration; here the client is this same
     *                   application, so they are read from the same place the published JWK Set
     *                   endpoint serves rather than over a self-call that only works once the
     *                   server is already listening.
     */
    public JwtSecuredAuthorizationRequestFilter(String authorizationEndpointUri,
                                                Supplier<JWKSet> clientKeys, String issuerUri,
                                                RSAKey decryptionKey,
                                                RegisteredClientRepository registeredClients) {
        this.decryptionKey = decryptionKey;
        this.registeredClients = registeredClients;
        this.authorizationEndpointMatcher =
                PathPatternRequestMatcher.withDefaults().matcher(authorizationEndpointUri);
        // Verified with Nimbus directly rather than NimbusJwtDecoder: that decoder pins the JWT type
        // to "JWT" and applies the check after any customization, so it cannot accept the
        // "oauth-authz-req+jwt" type RFC 9101 asks for.
        this.clientKeys = clientKeys;
        this.issuerUri = issuerUri;
    }

    /**
     * RFC 9101. When the authorization request arrives as a signed JWT, verify it and use the
     * parameters it carries. Spring Authorization Server has no notion of the {@code request}
     * parameter and would simply ignore it, acting on whatever the query string happened to say.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String requestObject = request.getParameter(REQUEST);
        if (!this.authorizationEndpointMatcher.matches(request) || !StringUtils.hasText(requestObject)) {
            filterChain.doFilter(request, response);
            return;
        }

        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        JWTClaimsSet claims;
        try {
            claims = verify(decryptIfEncrypted(requestObject, clientId),
                    registered(clientId, SIGNING_ALG_SETTING, DEFAULT_SIGNING_ALG));
        } catch (IllegalArgumentException ex) {
            log.debug("Rejecting request object: {}", ex.getMessage());
            writeError(response, "invalid_request_object", ex.getMessage());
            return;
        }

        Map<String, String[]> parameters = parametersFrom(claims);
        log.debug("Accepted a request object from [{}] carrying {}", claims.getIssuer(), parameters.keySet());
        filterChain.doFilter(new RequestObjectParameters(request, parameters), response);
    }

    /**
     * RFC 9101 section 6.2: a request object may be signed and then encrypted to the authorization
     * server, in which case what arrives is a JWE with the signed object inside. Everything after
     * this point is the same either way - the signature still has to be checked, because encryption
     * says only that nobody else read the request, not who wrote it.
     * <p>
     * An object that arrives unencrypted is passed straight through. Registering an encryption
     * algorithm is not a promise to always encrypt: OpenID Connect Dynamic Client Registration says
     * in as many words that the client may still send unencrypted request objects.
     *
     * @param clientId whose registration says which algorithms its request objects may arrive with
     * @return the signed request object, whether it arrived wrapped or not
     */
    private String decryptIfEncrypted(String requestObject, String clientId) {
        if (requestObject.split("\\.").length != 5) {
            return requestObject;
        }

        JWEObject encrypted;
        try {
            encrypted = JWEObject.parse(requestObject);
        } catch (ParseException ex) {
            throw new IllegalArgumentException("The request object is not a well-formed JWE");
        }

        String registeredAlg = registeredSetting(clientId, ENCRYPTION_ALG_SETTING);
        String registeredEnc = registeredSetting(clientId, ENCRYPTION_ENC_SETTING);
        if (registeredEnc != null && registeredAlg == null) {
            // The registration spec: when request_object_encryption_enc is included,
            // request_object_encryption_alg MUST also be provided. A registration that names a
            // content encryption method and nothing to wrap its key with is incomplete, and an
            // incomplete registration is not one this server can honour.
            throw new IllegalArgumentException("This client registered " + registeredEnc
                    + " and no algorithm to wrap the key with");
        }
        String expectedAlgorithm = registeredAlg == null ? DEFAULT_ENCRYPTION_ALG : registeredAlg;
        String expectedMethod = registeredEnc == null ? DEFAULT_ENCRYPTION_ENC : registeredEnc;

        String algorithm = String.valueOf(encrypted.getHeader().getAlgorithm());
        if (!algorithm.equals(expectedAlgorithm)) {
            // Stricter than the registration spec, which says the client may still use any other
            // algorithm the server supports. A declaration that constrains nothing leaves the choice
            // of key-wrapping algorithm with whoever sent the request.
            throw new IllegalArgumentException("The request object is encrypted with " + algorithm
                    + ", and this client registered " + expectedAlgorithm);
        }
        if (!SUPPORTED_ENCRYPTION_ALGS.contains(algorithm)) {
            // A registration cannot make this server offer an algorithm it does not implement, and
            // an algorithm left out of the supported set is left out deliberately.
            throw new IllegalArgumentException("This server does not decrypt " + algorithm
                    + " request objects");
        }

        String method = String.valueOf(encrypted.getHeader().getEncryptionMethod());
        if (!method.equals(expectedMethod)) {
            throw new IllegalArgumentException("The request object's content is encrypted with "
                    + method + ", and this client registered " + expectedMethod);
        }
        if (!SUPPORTED_ENCRYPTION_METHODS.contains(method)) {
            throw new IllegalArgumentException("This server does not decrypt " + method
                    + " content");
        }

        try {
            encrypted.decrypt(new RSADecrypter(this.decryptionKey));
        } catch (Exception ex) {
            throw new IllegalArgumentException(
                    "The request object could not be decrypted with this server's key");
        }
        log.debug("Decrypted a request object encrypted with {} / {}",
                encrypted.getHeader().getAlgorithm(), encrypted.getHeader().getEncryptionMethod());
        return encrypted.getPayload().toString();
    }

    /**
     * What this client registered, JARM-style: absent means the default rather than anything goes,
     * and an unregistered client is not one whose request objects mean anything.
     */
    private String registered(String clientId, String setting, String fallback) {
        String configured = registeredSetting(clientId, setting);
        return configured == null ? fallback : configured;
    }

    /** What this client registered for one setting, or null where it registered nothing. */
    private String registeredSetting(String clientId, String setting) {
        RegisteredClient client = clientId == null ? null
                : this.registeredClients.findByClientId(clientId);
        if (client == null) {
            return null;
        }
        Object configured = client.getClientSettings().getSetting(setting);
        return configured == null ? null : String.valueOf(configured);
    }

    /**
     * Checks the algorithm against the registration, the type, the signature against the client's
     * published key, the audience and the expiry. Any of them failing means the request object is
     * not one this server should act on.
     */
    private JWTClaimsSet verify(String requestObject, String expectedAlgorithm) {
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(requestObject);
        } catch (ParseException ex) {
            // An unsigned JWT parses as a plain one, never as a signed one, so alg: none lands here
            // rather than anywhere a signature could have been checked.
            throw new IllegalArgumentException("The request object is not a signed JWT");
        }
        String algorithm = String.valueOf(jwt.getHeader().getAlgorithm());
        if (!algorithm.equals(expectedAlgorithm)) {
            // RFC 9101 section 10.1 and the reason the setting exists: a client that registered one
            // algorithm and sent another is not a client being helpful, it is a request this server
            // has no agreement about. Accepting whatever arrives is how algorithm confusion starts.
            throw new IllegalArgumentException("The request object is signed with " + algorithm
                    + ", and this client registered " + expectedAlgorithm);
        }
        if (!SUPPORTED_SIGNING_ALGS.contains(algorithm)) {
            throw new IllegalArgumentException("This server does not check " + algorithm
                    + " signatures on request objects");
        }
        if (!REQUEST_OBJECT_TYPE.equals(String.valueOf(jwt.getHeader().getType()))) {
            // RFC 9101 section 10.8: the explicit type is what stops a JWT minted for something else
            // being passed off as an authorization request.
            throw new IllegalArgumentException("The request object must be typed " + REQUEST_OBJECT_TYPE);
        }

        try {
            JWK jwk = this.clientKeys.get().getKeyByKeyId(jwt.getHeader().getKeyID());
            if (!(jwk instanceof RSAKey rsaKey) || !jwt.verify(new RSASSAVerifier(rsaKey))) {
                throw new IllegalArgumentException("The request object signature does not verify");
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (!claims.getAudience().contains(this.issuerUri)) {
                // A request object signed for another authorization server must not be accepted.
                throw new IllegalArgumentException("The request object is for another audience");
            }
            if (claims.getExpirationTime() == null
                    || claims.getExpirationTime().toInstant().isBefore(Instant.now())) {
                throw new IllegalArgumentException("The request object has expired");
            }
            return claims;
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("The request object could not be verified: "
                    + ex.getMessage());
        }
    }

    private static Map<String, String[]> parametersFrom(JWTClaimsSet claims) {
        Map<String, String[]> parameters = new LinkedHashMap<>();
        claims.getClaims().forEach((name, value) -> {
            if (!JWT_CLAIMS.contains(name)) {
                parameters.put(name, new String[]{String.valueOf(value)});
            }
        });
        return parameters;
    }

    private static void writeError(HttpServletResponse response, String error, String description)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + error + "\",\"error_description\":\""
                + description.replace("\"", "'") + "\"}");
    }

    /**
     * Serves the authorization request parameters from the signed object and nothing else.
     * <p>
     * RFC 9101 section 6.1 is explicit: the server must use the parameters in the request object and
     * ignore what came alongside it. Anything appended to the URL is therefore invisible from here,
     * which is the whole guarantee — nothing between the client and the server can change what was
     * asked for.
     */
    private static final class RequestObjectParameters extends HttpServletRequestWrapper {

        private final Map<String, String[]> parameters;

        private RequestObjectParameters(HttpServletRequest request, Map<String, String[]> parameters) {
            super(request);
            this.parameters = parameters;
        }

        @Override
        public String getParameter(String name) {
            String[] values = this.parameters.get(name);
            return values == null ? null : values[0];
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            return Map.copyOf(this.parameters);
        }

        @Override
        public java.util.Enumeration<String> getParameterNames() {
            return java.util.Collections.enumeration(this.parameters.keySet());
        }

        @Override
        public String[] getParameterValues(String name) {
            return this.parameters.get(name);
        }

        /**
         * Rebuilt from the request object too. Spring Authorization Server decides which parameters
         * are query parameters by checking them against the raw query string, so overriding only
         * the parameter map would leave everything from the JWT filtered straight back out.
         */
        @Override
        public String getQueryString() {
            StringBuilder query = new StringBuilder();
            this.parameters.forEach((name, values) -> {
                if (!query.isEmpty()) {
                    query.append('&');
                }
                query.append(URLEncoder.encode(name, StandardCharsets.UTF_8))
                        .append('=')
                        .append(URLEncoder.encode(values[0], StandardCharsets.UTF_8));
            });
            return query.toString();
        }
    }
}
