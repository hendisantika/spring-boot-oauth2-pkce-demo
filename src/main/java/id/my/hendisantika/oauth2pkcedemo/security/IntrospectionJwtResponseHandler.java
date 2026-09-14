package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2TokenIntrospectionHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 08.15
 */
@Slf4j
public final class IntrospectionJwtResponseHandler implements AuthenticationSuccessHandler {

    /** RFC 9701 section 4: what the response is served as. */
    public static final String JWT_MEDIA_TYPE = "application/token-introspection+jwt";

    /**
     * And its {@code typ} header, which is the media type without the {@code application/} prefix -
     * the convention RFC 7519 section 5.1 allows and every JWT type follows.
     */
    public static final String JWT_TYPE = "token-introspection+jwt";

    /** The claim the ordinary RFC 7662 response is carried inside. */
    public static final String TOKEN_INTROSPECTION = "token_introspection";

    private final HttpMessageConverter<OAuth2TokenIntrospection> jsonConverter =
            new OAuth2TokenIntrospectionHttpMessageConverter();

    private final JwtEncoder jwtEncoder;
    private final String issuerUri;

    public IntrospectionJwtResponseHandler(JwtEncoder jwtEncoder, String issuerUri) {
        this.jwtEncoder = jwtEncoder;
        this.issuerUri = issuerUri;
    }

    /** Whether a caller asked for the signed form rather than plain JSON. */
    public static boolean wantsJwt(HttpServletRequest request) {
        String accept = request.getHeader(HttpHeaders.ACCEPT);
        return accept != null && accept.contains(JWT_MEDIA_TYPE);
    }

    /**
     * RFC 9701. An introspection response is ordinarily a bare JSON object: true of nothing in
     * particular, addressed to nobody, signed by no one. A resource server that wants to keep it,
     * forward it, or prove later what the authorization server said needs more than that - so the
     * same answer goes back as a JWT, naming the issuer, naming the caller as the audience, and
     * carrying the RFC 7662 object inside a {@code token_introspection} claim.
     * <p>
     * Spring Authorization Server has none of this: neither the media type nor the claim appears
     * anywhere in it, and the endpoint writes the JSON form unconditionally. This handler replaces
     * that, and only when the caller asks - a client that sends no {@code Accept} gets exactly what
     * it always did.
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2TokenIntrospectionAuthenticationToken introspection =
                (OAuth2TokenIntrospectionAuthenticationToken) authentication;
        OAuth2TokenIntrospection claims = introspection.getTokenClaims();

        if (!wantsJwt(request)) {
            this.jsonConverter.write(claims, null, new ServletServerHttpResponse(response));
            return;
        }

        String audience = audienceOf(introspection);
        Jwt jwt = sign(claims, audience);
        log.debug("Signed an introspection response for {}", audience);
        response.setContentType(JWT_MEDIA_TYPE);
        response.getWriter().write(jwt.getTokenValue());
    }

    private Jwt sign(OAuth2TokenIntrospection claims, String audience) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder claimsSet = JwtClaimsSet.builder()
                .issuer(issuerUri)
                .issuedAt(now)
                .claim(TOKEN_INTROSPECTION, jsonSafe(claims.getClaims()));
        if (audience != null) {
            // Addressed to the caller, so a response handed on to somebody else says whose it was.
            claimsSet.audience(List.of(audience));
        }
        return jwtEncoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256)
                        // RFC 9701 section 5: an explicit type, so this can never be mistaken for an
                        // access token by something that only checks the signature.
                        .type(JWT_TYPE)
                        .build(),
                claimsSet.build()));
    }

    /**
     * The introspection claims as JSON rather than as Java: RFC 7662's {@code exp}, {@code iat} and
     * {@code nbf} are numeric dates, and {@code scope} is one space-delimited string. Handing the
     * {@link Instant}s and collections straight to the signer fails outright - its serialiser cannot
     * see inside {@code java.time} - so the conversion is not a nicety.
     */
    private static Map<String, Object> jsonSafe(Map<String, Object> claims) {
        Map<String, Object> safe = new LinkedHashMap<>();
        claims.forEach((name, value) -> {
            if (value instanceof Instant instant) {
                safe.put(name, instant.getEpochSecond());
            } else if ("scope".equals(name) && value instanceof Collection<?> scopes) {
                safe.put(name, scopes.stream().map(String::valueOf).collect(Collectors.joining(" ")));
            } else if (value instanceof Collection<?> collection) {
                safe.put(name, collection.stream().map(String::valueOf).toList());
            } else if (value instanceof URL url) {
                safe.put(name, url.toExternalForm());
            } else {
                safe.put(name, value);
            }
        });
        return safe;
    }

    /** The client that asked, which is the only party the answer is addressed to. */
    private static String audienceOf(OAuth2TokenIntrospectionAuthenticationToken introspection) {
        if (introspection.getPrincipal() instanceof OAuth2ClientAuthenticationToken client
                && client.getRegisteredClient() != null) {
            return client.getRegisteredClient().getClientId();
        }
        return null;
    }

    /** Reads the inner object back out, for anything that wants the RFC 7662 shape. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> introspectionOf(Jwt jwt) {
        Object claim = jwt.getClaim(TOKEN_INTROSPECTION);
        return claim instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }
}
