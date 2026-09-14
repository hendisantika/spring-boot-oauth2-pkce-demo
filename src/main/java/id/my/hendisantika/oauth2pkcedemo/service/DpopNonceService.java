package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.DpopNonceController;
import id.my.hendisantika.oauth2pkcedemo.controller.NonceApiController;
import id.my.hendisantika.oauth2pkcedemo.security.DpopKeyPair;
import id.my.hendisantika.oauth2pkcedemo.security.DpopNonceAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.DpopNonceRequiredFilter;
import id.my.hendisantika.oauth2pkcedemo.security.DpopNonceRun;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 23.05
 */
@Slf4j
@Service
public class DpopNonceService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;

    public DpopNonceService(DemoProperties properties) {
        this.properties = properties;
    }

    public String clientId() {
        return properties.dpopNonceClient().clientId();
    }

    public String apiUri() {
        return properties.issuerUri() + NonceApiController.NONCE_API_URI;
    }

    /**
     * Gets a DPoP-bound token, then calls the protected resource five ways: without a nonce, with
     * the one it was just given, with that same one again, with one nobody issued, and with the
     * fresh one the successful call came back with.
     */
    public DpopNonceRun run() {
        Probe probe = new Probe();
        DpopKeyPair key = DpopKeyPair.generate();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());
        String accessToken = probe.token(key);

        List<DpopNonceAttempt> attempts = new ArrayList<>();
        DpopNonceAttempt first = probe.call("With a proof carrying no nonce", key, accessToken, null);
        attempts.add(first);

        String given = first.nonceGivenBack();
        DpopNonceAttempt second = probe.call("With the nonce the server just gave", key, accessToken, given);
        attempts.add(second);
        attempts.add(probe.call("With that same nonce again", key, accessToken, given));
        attempts.add(probe.call("With a nonce nobody issued", key, accessToken, randomUrlSafe(16)));
        attempts.add(probe.call("With the fresh one the accepted call returned", key, accessToken,
                second.nonceGivenBack()));

        log.debug("DPoP nonce run finished; {} of {} accepted",
                attempts.stream().filter(DpopNonceAttempt::isAccepted).count(), attempts.size());
        return new DpopNonceRun(clientId(), key.thumbprint(), boundThumbprint(accessToken),
                List.copyOf(attempts), Instant.now());
    }

    /** RFC 9449 section 6.1: what the issued token says it is tied to. */
    @SuppressWarnings("unchecked")
    private static String boundThumbprint(String accessToken) {
        try {
            Object cnf = JWTParser.parse(accessToken).getJWTClaimsSet().getClaim("cnf");
            return cnf instanceof Map<?, ?> map ? String.valueOf(((Map<String, Object>) map).get("jkt")) : null;
        } catch (Exception ex) {
            return null;
        }
    }

    /** A client with a browser, a key, and no secret. */
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

        /** An ordinary code flow, with a proof on the token request so the token comes back bound. */
        @SuppressWarnings("unchecked")
        private String token(DpopKeyPair key) {
            String verifier = randomUrlSafe(32);
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId())
                    .queryParam(OAuth2ParameterNames.SCOPE,
                            String.join(" ", properties.dpopNonceClient().scopes()))
                    .queryParam(OAuth2ParameterNames.REDIRECT_URI, base + DpopNonceController.CALLBACK_URI)
                    .queryParam(OAuth2ParameterNames.STATE, randomUrlSafe(16))
                    .queryParam("code_challenge", codeChallenge(verifier))
                    .queryParam("code_challenge_method", "S256")
                    .build().encode(StandardCharsets.UTF_8).toUriString();

            String location = restClient.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        return next == null ? null : URI.create(base).resolve(next).toString();
                    }, false);
            String code = location == null ? null : parameterOf(location, OAuth2ParameterNames.CODE);
            if (code == null) {
                throw new IllegalStateException("The authorization request produced no code");
            }

            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add(OAuth2ParameterNames.GRANT_TYPE, "authorization_code");
            form.add(OAuth2ParameterNames.CODE, code);
            form.add(OAuth2ParameterNames.REDIRECT_URI, base + DpopNonceController.CALLBACK_URI);
            form.add(OAuth2ParameterNames.CLIENT_ID, clientId());
            form.add("code_verifier", verifier);

            Map<String, Object> body = restClient.post()
                    .uri(base + "/oauth2/token")
                    // RFC 9449 section 5: the proof on the token request is what binds the token.
                    .header(DpopNonceRequiredFilter.DPOP_HEADER,
                            key.proof("POST", base + "/oauth2/token", null))
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(Map.class);
            if (body == null || body.get("access_token") == null) {
                throw new IllegalStateException("The token endpoint issued nothing");
            }
            return String.valueOf(body.get("access_token"));
        }

        /** One call, and whatever the resource server said about the nonce in the proof. */
        @SuppressWarnings("unchecked")
        private DpopNonceAttempt call(String label, DpopKeyPair key, String accessToken, String nonce) {
            return restClient.get()
                    .uri(URI.create(apiUri()))
                    .header(HttpHeaders.AUTHORIZATION, "DPoP " + accessToken)
                    .header(DpopNonceRequiredFilter.DPOP_HEADER,
                            key.proof("GET", apiUri(), accessToken, nonce))
                    .exchange((request, response) -> {
                        Map<String, Object> body = response.bodyTo(Map.class);
                        return new DpopNonceAttempt(label, nonce,
                                response.getStatusCode().value(),
                                body == null ? null : (String) body.get("error"),
                                response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE),
                                response.getHeaders().getFirst(DpopNonceRequiredFilter.NONCE_HEADER));
                    }, false);
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
