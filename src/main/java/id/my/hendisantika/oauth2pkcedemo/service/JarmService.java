package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.JarmController;
import id.my.hendisantika.oauth2pkcedemo.security.JarmAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.JarmResponseFilter;
import id.my.hendisantika.oauth2pkcedemo.security.JarmRun;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
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
 * Time: 11.30
 */
@Slf4j
@Service
public class JarmService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final JwtDecoder jwtDecoder;

    public JarmService(DemoProperties properties, JwtDecoder jwtDecoder) {
        this.properties = properties;
        this.jwtDecoder = jwtDecoder;
    }

    public String clientId() {
        return properties.jarmClient().clientId();
    }

    /**
     * Asks for the same authorization five ways: in the clear, signed, signed after a failure, with
     * the signed answer tampered with, and asking for a mode nothing here implements.
     */
    public JarmRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        List<JarmAttempt> attempts = new ArrayList<>();
        attempts.add(probe.authorize("The ordinary response", "query", "openid profile", null));
        JarmAttempt signed = probe.authorize("Asked for a signed response", "jwt", "openid profile", null);
        attempts.add(signed);
        attempts.add(probe.authorize("A refusal, signed the same way", "jwt", "openid admin.everything",
                "The scope is not one the client registered, so the answer is an error - carried "
                        + "exactly like a code would be."));
        attempts.add(tampered(signed));
        attempts.add(probe.authorize("Asked for a mode nothing here implements", "form_post",
                "openid profile",
                "form_post is a real JARM delivery mode and this demo has not implemented it. "
                        + "Nothing says so: the answer comes back in the clear."));

        log.debug("JARM run finished; {} of {} answers were signed",
                attempts.stream().filter(JarmAttempt::signed).count(), attempts.size());
        return new JarmRun(clientId(), List.copyOf(attempts), Instant.now());
    }

    /**
     * One character of the payload changed. Nothing about the JWT looks different until the
     * signature is checked, which is the entire point of checking it.
     */
    private JarmAttempt tampered(JarmAttempt signed) {
        if (!signed.signed() || signed.jwt() == null) {
            return new JarmAttempt("The signed answer, with the code changed", "jwt", Map.of(),
                    true, false, Map.of(), null, "There was no signed answer to tamper with.");
        }
        String[] parts = signed.jwt().split("\\.");
        Map<String, Object> claims = new LinkedHashMap<>(signed.claims());
        claims.put(OAuth2ParameterNames.CODE, "a-code-of-my-own-choosing");
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                toJson(claims).getBytes(StandardCharsets.UTF_8));
        String forged = parts[0] + "." + payload + "." + parts[2];

        Boolean verifies;
        try {
            jwtDecoder.decode(forged);
            verifies = true;
        } catch (Exception ex) {
            verifies = false;
        }
        return new JarmAttempt("The signed answer, with the code changed", "jwt", Map.of(),
                true, verifies, new TreeMap<>(claims), forged,
                "The same header and the same signature, over a payload that now names a different "
                        + "code.");
    }

    /** Small enough to write by hand, and it only ever has to survive being rejected. */
    private static String toJson(Map<String, Object> claims) {
        StringBuilder json = new StringBuilder("{");
        claims.forEach((name, value) -> {
            if (json.length() > 1) {
                json.append(',');
            }
            json.append('"').append(name).append("\":");
            if (value instanceof Number || value instanceof Boolean) {
                json.append(value);
            } else if (value instanceof Instant instant) {
                json.append(instant.getEpochSecond());
            } else {
                json.append('"').append(String.valueOf(value).replace("\"", "\\\"")).append('"');
            }
        });
        return json.append('}').toString();
    }

    /** A browser with a session, asking for authorization and reading whatever comes back. */
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

        /** One authorization request, and the response exactly as the browser would receive it. */
        private JarmAttempt authorize(String label, String responseMode, String scope, String note) {
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId())
                    .queryParam(OAuth2ParameterNames.SCOPE, scope)
                    .queryParam(OAuth2ParameterNames.REDIRECT_URI, base + JarmController.CALLBACK_URI)
                    .queryParam(OAuth2ParameterNames.STATE, randomUrlSafe(16))
                    .queryParam("code_challenge", codeChallenge(randomUrlSafe(32)))
                    .queryParam("code_challenge_method", "S256")
                    .queryParam(JarmResponseFilter.RESPONSE_MODE, responseMode)
                    .build().encode(StandardCharsets.UTF_8).toUriString();

            String location = restClient.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        return next == null ? null : URI.create(base).resolve(next).toString();
                    }, false);

            Map<String, String> parameters = location == null ? Map.of() : parametersOf(location);
            String jwt = parameters.get(JarmResponseFilter.RESPONSE);
            if (jwt == null) {
                // Abbreviated only for the page: a code is long and says nothing by being complete.
                return new JarmAttempt(label, responseMode, forDisplay(parameters), false, null,
                        Map.of(), null, note);
            }
            try {
                Jwt decoded = jwtDecoder.decode(jwt);
                return new JarmAttempt(label, responseMode, Map.of("response", abbreviate(jwt)), true,
                        true, new TreeMap<>(decoded.getClaims()), jwt, note);
            } catch (Exception ex) {
                log.debug("The signed authorization response did not verify: {}", ex.getMessage());
                return new JarmAttempt(label, responseMode, Map.of("response", abbreviate(jwt)), true,
                        false, Map.of(), jwt, note);
            }
        }
    }

    /** Long values shortened, because the page is about their presence rather than their content. */
    private static Map<String, String> forDisplay(Map<String, String> parameters) {
        Map<String, String> shortened = new LinkedHashMap<>();
        parameters.forEach((name, value) -> shortened.put(name, abbreviate(value)));
        return shortened;
    }

    private static Map<String, String> parametersOf(String location) {
        Map<String, String> parameters = new LinkedHashMap<>();
        int query = location.indexOf('?');
        if (query < 0) {
            return parameters;
        }
        for (String pair : location.substring(query + 1).split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0) {
                parameters.put(URLDecoder.decode(pair.substring(0, equals), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8));
            }
        }
        return parameters;
    }

    private static String abbreviate(String value) {
        return value.length() <= 42 ? value : value.substring(0, 42) + "\u2026";
    }

    private static String csrf(String page) {
        Matcher matcher = CSRF.matcher(page == null ? "" : page);
        return matcher.find() ? matcher.group(1) : "";
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
