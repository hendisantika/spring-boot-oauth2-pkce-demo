package id.my.hendisantika.oauth2pkcedemo.security;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 17.48
 */
@Slf4j
public final class DpopBoundAuthorizationCodeFilter extends OncePerRequestFilter {

    /** RFC 9449 section 10: the authorization request parameter carrying the key's thumbprint. */
    public static final String DPOP_JKT = "dpop_jkt";

    private static final String DPOP_HEADER = "DPoP";
    private static final JOSEObjectType DPOP_JWT = new JOSEObjectType("dpop+jwt");

    /** How the authorization is looked up while the code is still outstanding. */
    private static final OAuth2TokenType AUTHORIZATION_CODE =
            new OAuth2TokenType(OAuth2ParameterNames.CODE);

    private final RequestMatcher tokenEndpointMatcher;
    private final OAuth2AuthorizationService authorizationService;

    public DpopBoundAuthorizationCodeFilter(String tokenEndpointUri,
                                            OAuth2AuthorizationService authorizationService) {
        this.tokenEndpointMatcher = PathPatternRequestMatcher.withDefaults()
                .matcher(HttpMethod.POST, tokenEndpointUri);
        this.authorizationService = authorizationService;
    }

    /**
     * RFC 9449 section 10. An authorization request may name the key its code should be bound to;
     * the token request then has to prove possession of that key. Spring Authorization Server knows
     * nothing of {@code dpop_jkt} - it stores it with the rest of the request and never looks at it
     * again - so the check happens here, before the token endpoint sees the request at all. That
     * ordering matters: rejecting early leaves the authorization code untouched and still
     * redeemable by the client it belongs to.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String boundThumbprint = boundThumbprint(request);
        if (boundThumbprint == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String proof = request.getHeader(DPOP_HEADER);
        if (!StringUtils.hasText(proof)) {
            log.debug("Rejecting a token request for a code bound to [{}]: no DPoP proof", boundThumbprint);
            writeError(response, "The authorization code is bound to a DPoP key (dpop_jkt="
                    + boundThumbprint + ") and the token request carried no DPoP proof");
            return;
        }

        String presentedThumbprint;
        try {
            presentedThumbprint = thumbprintOf(proof);
        } catch (IllegalArgumentException ex) {
            writeError(response, ex.getMessage());
            return;
        }

        if (!MessageDigest.isEqual(boundThumbprint.getBytes(StandardCharsets.US_ASCII),
                presentedThumbprint.getBytes(StandardCharsets.US_ASCII))) {
            log.debug("Rejecting a token request: code bound to [{}], proof signed by [{}]",
                    boundThumbprint, presentedThumbprint);
            writeError(response, "The authorization code is bound to the key " + boundThumbprint
                    + ", but the DPoP proof was signed by " + presentedThumbprint);
            return;
        }

        log.debug("Token request carries a proof for the bound key [{}]", boundThumbprint);
        filterChain.doFilter(request, response);
    }

    /**
     * @return the thumbprint the authorization request asked the code to be bound to, or
     *         {@code null} when this is not an authorization code request, when the code is unknown,
     *         or when no binding was requested - all of which leave nothing to enforce
     */
    private String boundThumbprint(HttpServletRequest request) {
        if (!this.tokenEndpointMatcher.matches(request)) {
            return null;
        }
        if (!AuthorizationGrantType.AUTHORIZATION_CODE.getValue()
                .equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))) {
            return null;
        }
        String code = request.getParameter(OAuth2ParameterNames.CODE);
        if (!StringUtils.hasText(code)) {
            return null;
        }

        OAuth2Authorization authorization = this.authorizationService.findByToken(code, AUTHORIZATION_CODE);
        if (authorization == null) {
            // An unknown or already redeemed code. Left to the token endpoint, which answers
            // invalid_grant either way.
            return null;
        }
        OAuth2AuthorizationRequest authorizationRequest =
                authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
        if (authorizationRequest == null) {
            return null;
        }
        Object jkt = authorizationRequest.getAdditionalParameters().get(DPOP_JKT);
        return jkt == null || !StringUtils.hasText(String.valueOf(jkt)) ? null : String.valueOf(jkt);
    }

    /**
     * The thumbprint of the key the proof was actually signed with. The public key travels inside
     * the proof's own header, so it is only worth anything once the signature over it verifies -
     * otherwise anyone could copy the victim's public key into a header and be believed.
     */
    private static String thumbprintOf(String proof) {
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(proof);
        } catch (ParseException ex) {
            throw new IllegalArgumentException("The DPoP proof is not a signed JWT");
        }
        if (!DPOP_JWT.equals(jwt.getHeader().getType())) {
            throw new IllegalArgumentException("The DPoP proof must be typed dpop+jwt");
        }

        JWK jwk = jwt.getHeader().getJWK();
        if (jwk == null || jwk.isPrivate()) {
            throw new IllegalArgumentException("The DPoP proof must carry the public key in its jwk header");
        }
        try {
            JWSVerifier verifier = switch (jwk) {
                case ECKey ecKey -> new ECDSAVerifier(ecKey);
                case RSAKey rsaKey -> new RSASSAVerifier(rsaKey);
                default -> throw new IllegalArgumentException(
                        "Unsupported DPoP proof key type " + jwk.getKeyType());
            };
            if (!jwt.verify(verifier)) {
                throw new IllegalArgumentException("The DPoP proof signature does not verify");
            }
            return jwk.computeThumbprint().toString();
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("The DPoP proof could not be verified: " + ex.getMessage());
        }
    }

    /**
     * RFC 9449 says only that the request must be rejected, without naming an error code.
     * {@code invalid_grant} is the accurate one: the code itself is what cannot be redeemed here.
     */
    private static void writeError(HttpServletResponse response, String description) throws IOException {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + OAuth2ErrorCodes.INVALID_GRANT
                + "\",\"error_description\":\"" + description.replace("\"", "'") + "\"}");
    }
}
