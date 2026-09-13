package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.IdTokenBindingRun;
import id.my.hendisantika.oauth2pkcedemo.security.IdTokenCheck;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 11.05
 */
@Slf4j
@Service
public class IdTokenBindingService {

    private final JwtDecoder jwtDecoder;
    private final ClientRegistrationRepository clientRegistrations;
    private final DemoProperties properties;
    private final RestClient restClient;

    public IdTokenBindingService(JwtDecoder jwtDecoder, ClientRegistrationRepository clientRegistrations,
                                 DemoProperties properties) {
        this.jwtDecoder = jwtDecoder;
        this.clientRegistrations = clientRegistrations;
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    public String otherClientId() {
        return properties.exchangeClient().clientId();
    }

    /**
     * Puts the session's own ID token through the checks a client makes, and then two substitutions
     * those checks say nothing about.
     */
    public IdTokenBindingRun run(OidcIdToken idToken, OAuth2AccessToken accessToken,
                                 String registrationId) {
        // Decoding verifies the signature against the server's published keys, which is step one of
        // OpenID Connect Core 3.1.3.7 and the thing every later check depends on.
        Jwt decoded = jwtDecoder.decode(idToken.getTokenValue());

        List<IdTokenCheck> checks = new ArrayList<>();
        checks.add(validated("At the client it was issued to",
                "OidcIdTokenValidator, the same instance Spring Security runs on every login.",
                registrationId, decoded, false));
        checks.add(validated("Replayed at another client",
                "The same token, handed to a client it does not name.",
                properties.confidentialClient().registrationId(), decoded, true));
        checks.add(nonceCheck(decoded));

        String issuedTokenHash = atHash(accessToken.getTokenValue());
        String otherToken = clientCredentialsToken();
        String otherTokenHash = otherToken == null ? null : atHash(otherToken);
        checks.add(accessTokenCheck(decoded, issuedTokenHash, otherTokenHash));
        checks.add(possessionCheck(decoded));

        log.debug("ID token binding run for {} finished with {} gaps", decoded.getSubject(),
                checks.stream().filter(IdTokenCheck::isGap).count());

        return new IdTokenBindingRun(new TreeMap<>(decoded.getClaims()), decoded.getSubject(),
                issuedTokenHash, otherTokenHash, subjectOf(otherToken),
                decoded.hasClaim("at_hash"), decoded.hasClaim("cnf"), checks, Instant.now());
    }

    /** Spring Security's own validator, pointed at one registration or another. */
    private IdTokenCheck validated(String label, String description, String registrationId,
                                   Jwt decoded, boolean attack) {
        ClientRegistration registration = clientRegistrations.findByRegistrationId(registrationId);
        OAuth2TokenValidatorResult result = new OidcIdTokenValidator(registration).validate(decoded);
        if (!result.hasErrors()) {
            return new IdTokenCheck(label, description, "accepted",
                    "Every claim the specification names was checked and none of them refused it.",
                    false, attack);
        }
        String detail = result.getErrors().stream().map(OAuth2Error::getDescription)
                .filter(java.util.Objects::nonNull).findFirst()
                .orElse(result.getErrors().iterator().next().getErrorCode());
        return new IdTokenCheck(label, description, "refused", detail, true, attack);
    }

    /**
     * The comparison {@code OidcAuthorizationCodeAuthenticationProvider} makes after the validator
     * has run. The claim holds a <em>hash</em> of the nonce: Spring's client sends
     * {@code createHash(nonce)} in the authorization request and keeps the value itself, so a
     * different request can never produce this claim.
     */
    private static IdTokenCheck nonceCheck(Jwt decoded) {
        String claim = decoded.getClaimAsString("nonce");
        String expected = sha256("a-nonce-from-some-other-authorization-request");
        boolean refused = claim == null || !claim.equals(expected);
        return new IdTokenCheck("Replayed into another authorization request",
                "A client comparing this token against a nonce it generated for a different login.",
                refused ? "refused" : "accepted",
                refused
                        ? "invalid_nonce: the claim is " + abbreviate(claim)
                        + ", the waiting request hashed to " + abbreviate(expected) + "."
                        : "The hashes matched, which they should not have.",
                refused, true);
    }

    /**
     * OpenID Connect Core 3.1.3.6 defines at_hash for exactly this, and makes it OPTIONAL when the
     * ID token comes from the token endpoint. This server omits it, so there is nothing to compare.
     */
    private static IdTokenCheck accessTokenCheck(Jwt decoded, String issuedTokenHash,
                                                 String otherTokenHash) {
        if (decoded.hasClaim("at_hash")) {
            boolean matches = decoded.getClaimAsString("at_hash").equals(issuedTokenHash);
            return new IdTokenCheck("Paired with a different access token",
                    "The ID token from this login, handed over with somebody else's access token.",
                    matches ? "accepted" : "refused",
                    "at_hash is present and " + (matches ? "matches" : "does not match") + ".",
                    !matches, true);
        }
        String substitute = otherTokenHash == null
                ? "no second token could be minted to substitute"
                : "the substitute to " + abbreviate(otherTokenHash);
        return new IdTokenCheck("Paired with a different access token",
                "The ID token from this login, handed over with somebody else's access token.",
                "accepted",
                "No at_hash claim. The token it came with hashes to " + abbreviate(issuedTokenHash)
                        + " and " + substitute + ", and the ID token names neither.",
                false, true);
    }

    /**
     * RFC 7800 would carry a key here. Nothing does: the validator's own signature takes the ID
     * token and nothing else, so there is no key for a holder to prove.
     */
    private static IdTokenCheck possessionCheck(Jwt decoded) {
        boolean bound = decoded.hasClaim("cnf");
        return new IdTokenCheck("Presented by whoever is holding it",
                "The same token, replayed by someone who took it rather than earned it.",
                bound ? "refused" : "accepted",
                bound ? "A cnf claim is present." : "No cnf claim, and nothing asked for a proof.",
                bound, true);
    }

    /** A real access token belonging to somebody else, to stand in for the substituted one. */
    @SuppressWarnings("unchecked")
    private String clientCredentialsToken() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("scope", "api.read");
        DemoProperties.Client client = properties.exchangeClient();
        String credentials = client.clientId() + ":" + client.clientSecret();
        try {
            Map<String, Object> body = restClient.post()
                    .uri("/oauth2/token")
                    .header("Authorization", "Basic " + Base64.getEncoder()
                            .encodeToString(credentials.getBytes(StandardCharsets.UTF_8)))
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(Map.class);
            return body == null ? null : String.valueOf(body.get("access_token"));
        } catch (Exception ex) {
            log.warn("Unable to mint a second access token: {}", ex.getMessage());
            return null;
        }
    }

    private String subjectOf(String accessToken) {
        try {
            return accessToken == null ? null : jwtDecoder.decode(accessToken).getSubject();
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * OpenID Connect Core 3.1.3.6: the left-most half of the SHA-256 of the token's ASCII octets,
     * base64url encoded. Computed here so the page can show the claim that is not there.
     */
    public static String atHash(String accessToken) {
        byte[] digest = digest(accessToken);
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Arrays.copyOf(digest, digest.length / 2));
    }

    /** The whole digest, which is what Spring's client puts in the nonce parameter. */
    private static String sha256(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest(value));
    }

    private static byte[] digest(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII));
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    private static String abbreviate(String value) {
        if (value == null) {
            return "nothing";
        }
        return value.length() <= 16 ? value : value.substring(0, 16) + "…";
    }
}
