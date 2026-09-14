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

    /** Where the self-submitting page says the response is going, shown beside what it carries. */
    private static final String FORM_ACTION = "form action";

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
        attempts.add(probe.authorize("Delivered after the hash", JarmResponseFilter.FRAGMENT_JWT,
                "openid profile",
                "The same JWT in the fragment, which a browser never sends to the server the URI "
                        + "points at - so the response stays out of that server's logs."));
        attempts.add(probe.authorize("Delivered in a form the browser posts",
                JarmResponseFilter.FORM_POST_JWT, "openid profile",
                "No URL carries it at all: the authorization server answers with a page that "
                        + "submits itself, and the client reads its own request body."));
        attempts.add(probe.authorize("Asked for a mode nothing here implements", "fragment",
                "openid profile",
                "fragment without the .jwt is an ordinary response mode, and nothing here reads "
                        + "it. The answer comes back on the query string as if it had not been asked "
                        + "for."));

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

    /** Either a redirect somewhere, or a page to read. A JARM answer can be either. */
    private record Answer(String location, String body) {
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

            Answer answer = restClient.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        return new Answer(next == null ? null : URI.create(base).resolve(next).toString(),
                                next == null ? response.bodyTo(String.class) : null);
                    }, false);

            String location = answer.location();
            Map<String, String> parameters = location != null
                    ? parametersOf(location)
                    : formPostParameters(answer.body());
            String jwt = parameters.get(JarmResponseFilter.RESPONSE);
            if (jwt == null) {
                // Abbreviated only for the page: a code is long and says nothing by being complete.
                return new JarmAttempt(label, responseMode, forDisplay(parameters), false, null,
                        Map.of(), null, note);
            }
            Map<String, String> shown = new LinkedHashMap<>();
            if (parameters.containsKey(FORM_ACTION)) {
                shown.put(FORM_ACTION, parameters.get(FORM_ACTION));
                // Submitting it is the last step a browser would take on its own, and the only way
                // to say where the response ended up rather than where it was told to go.
                shown.put("the client received", submit(parameters.get(FORM_ACTION), jwt));
            }
            shown.put(JarmResponseFilter.RESPONSE, abbreviate(jwt));

            try {
                Jwt decoded = jwtDecoder.decode(jwt);
                return new JarmAttempt(label, responseMode, shown, true, true,
                        new TreeMap<>(decoded.getClaims()), jwt, note);
            } catch (Exception ex) {
                log.debug("The signed authorization response did not verify: {}", ex.getMessage());
                return new JarmAttempt(label, responseMode, shown, true, false, Map.of(), jwt, note);
            }
        }

        /** Posts the form the way the browser would, and reports what came back. */
        @SuppressWarnings("unchecked")
        private String submit(String action, String jwt) {
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add(JarmResponseFilter.RESPONSE, jwt);
            try {
                Map<String, Object> received = restClient.post()
                        .uri(URI.create(action))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .body(form)
                        .retrieve()
                        .body(Map.class);
                return received == null
                        ? "nothing"
                        : received.get("delivered_in") + ", " + received.get("characters")
                        + " characters";
            } catch (Exception ex) {
                return "the post was refused: " + ex.getMessage();
            }
        }
    }

    /**
     * A form_post.jwt answer is not a redirect at all: it is a page whose only job is to submit
     * itself. Reading the hidden field out of it is what a browser does a moment later.
     */
    private static Map<String, String> formPostParameters(String body) {
        Map<String, String> parameters = new LinkedHashMap<>();
        if (body == null) {
            return parameters;
        }
        Matcher action = Pattern.compile("action=\"([^\"]+)\"").matcher(body);
        if (action.find()) {
            parameters.put(FORM_ACTION, action.group(1));
        }
        Matcher field = Pattern.compile("name=\"([^\"]+)\"\\s+value=\"([^\"]+)\"").matcher(body);
        while (field.find()) {
            parameters.put(field.group(1), field.group(2).replace("&quot;", "\"").replace("&amp;", "&"));
        }
        return parameters;
    }

    /** Long values shortened, because the page is about their presence rather than their content. */
    private static Map<String, String> forDisplay(Map<String, String> parameters) {
        Map<String, String> shortened = new LinkedHashMap<>();
        parameters.forEach((name, value) -> shortened.put(name, abbreviate(value)));
        return shortened;
    }

    /** The parameters, whether they came before the {@code #} or after it. */
    private static Map<String, String> parametersOf(String location) {
        Map<String, String> parameters = new LinkedHashMap<>();
        int fragment = location.indexOf('#');
        int query = fragment >= 0 ? fragment : location.indexOf('?');
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
