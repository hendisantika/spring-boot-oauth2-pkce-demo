package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.JarmController;
import id.my.hendisantika.oauth2pkcedemo.security.JarmClientKeys;
import id.my.hendisantika.oauth2pkcedemo.security.JarmEncryptionRun;
import id.my.hendisantika.oauth2pkcedemo.security.JarmResponseFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 17.05
 */
@Slf4j
@Service
public class JarmEncryptionService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    /** The claims a signed response hands to anyone who has the URL. */
    private static final List<String> INTERESTING = List.of("code", "state", "iss", "aud");

    private final DemoProperties properties;
    private final JwtDecoder jwtDecoder;
    private final JarmClientKeys clientKeys;

    public JarmEncryptionService(DemoProperties properties, JwtDecoder jwtDecoder,
                                 JarmClientKeys clientKeys) {
        this.properties = properties;
        this.jwtDecoder = jwtDecoder;
        this.clientKeys = clientKeys;
    }

    public String signedOnlyClientId() {
        return properties.jarmClient().clientId();
    }

    public String encryptedClientId() {
        return properties.jarmEncryptedClient().clientId();
    }

    /**
     * Two clients, two answers: one signed, one signed and then encrypted. The signed one is read
     * without any key at all, which is the whole difference.
     */
    public JarmEncryptionRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        String signed = probe.authorize(properties.jarmClient());
        String encrypted = probe.authorize(properties.jarmEncryptedClient());

        String nested = encrypted == null ? null : clientKeys.decrypt(encrypted);
        Map<String, Object> claims = Map.of();
        boolean verifies = false;
        if (nested != null) {
            try {
                claims = new TreeMap<>(jwtDecoder.decode(nested).getClaims());
                verifies = true;
            } catch (Exception ex) {
                log.debug("The nested signed response did not verify: {}", ex.getMessage());
            }
        }

        log.debug("JARM encryption run finished; nested JWT {}", verifies ? "verified" : "did not verify");
        return new JarmEncryptionRun(signedOnlyClientId(), encryptedClientId(), clientKeys.keyId(),
                readableWithoutAKey(signed), signed, encrypted, headerOf(encrypted), nested, claims,
                verifies, Instant.now());
    }

    /**
     * What anyone holding the signed response can read from it: a JWS body is base64, not
     * ciphertext, so every claim is in plain sight to a log, a browser history or a referrer header.
     */
    private static List<String> readableWithoutAKey(String signedJwt) {
        if (signedJwt == null) {
            return List.of();
        }
        try {
            var claims = JWTParser.parse(signedJwt).getJWTClaimsSet();
            return INTERESTING.stream().filter(name -> claims.getClaim(name) != null).toList();
        } catch (Exception ex) {
            return List.of();
        }
    }

    /** The JWE header, which stays readable by design - it says how to undo the encryption. */
    private static Map<String, Object> headerOf(String jwe) {
        try {
            return jwe == null ? Map.of() : new TreeMap<>(JWEObject.parse(jwe).getHeader().toJSONObject());
        } catch (Exception ex) {
            return Map.of();
        }
    }

    /** A browser with a session, asking each client's authorization request in turn. */
    private final class Probe {

        private final RestClient restClient;
        private final String base = properties.issuerUri();

        private Probe() {
            HttpClient httpClient = HttpClient.newBuilder()
                    .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
            this.restClient = RestClient.builder()
                    .requestFactory(new JdkClientHttpRequestFactory(httpClient))
                    .build();
        }

        private void signIn(String username, String password) {
            String page = restClient.get().uri(base + "/login").retrieve().body(String.class);
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("username", username);
            form.add("password", password);
            form.add("_csrf", csrf(page));
            restClient.post()
                    .uri(base + "/login")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .exchange((request, response) -> response.getStatusCode().value(), false);
        }

        private String authorize(DemoProperties.Client client) {
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, client.clientId())
                    .queryParam(OAuth2ParameterNames.SCOPE, String.join(" ", client.scopes()))
                    .queryParam(OAuth2ParameterNames.REDIRECT_URI, base + JarmController.CALLBACK_URI)
                    .queryParam(OAuth2ParameterNames.STATE, randomUrlSafe(16))
                    .queryParam("code_challenge", codeChallenge(randomUrlSafe(32)))
                    .queryParam("code_challenge_method", "S256")
                    .queryParam(JarmResponseFilter.RESPONSE_MODE, "jwt")
                    .build().encode(StandardCharsets.UTF_8).toUriString();

            String location = restClient.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        return next == null ? null : URI.create(base).resolve(next).toString();
                    }, false);
            return location == null ? null : parameterOf(location, JarmResponseFilter.RESPONSE);
        }
    }

    private static String csrf(String page) {
        Matcher matcher = CSRF.matcher(page == null ? "" : page);
        return matcher.find() ? matcher.group(1) : "";
    }

    private static String parameterOf(String uri, String name) {
        Matcher matcher = Pattern.compile("[?&]" + name + "=([^&]*)").matcher(uri);
        return matcher.find() ? URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8) : null;
    }

    private static String codeChallenge(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    private static String randomUrlSafe(int bytes) {
        byte[] value = new byte[bytes];
        RANDOM.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}
