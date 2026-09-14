package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.RequestUriController;
import id.my.hendisantika.oauth2pkcedemo.security.RequestUriAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.RequestUriRun;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
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
import java.time.Duration;
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
 * Time: 19.05
 */
@Slf4j
@Service
public class RequestUriService {

    /** How Spring Authorization Server builds the value, and the only part of it that is opaque. */
    public static final String PREFIX = "urn:ietf:params:oauth:request_uri:";
    public static final String DELIMITER = "___";

    private static final OAuth2TokenType STATE_TOKEN_TYPE =
            new OAuth2TokenType(OAuth2ParameterNames.STATE);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final OAuth2AuthorizationService authorizationService;

    public RequestUriService(DemoProperties properties, OAuth2AuthorizationService authorizationService) {
        this.properties = properties;
        this.authorizationService = authorizationService;
    }

    public String clientId() {
        return properties.requestUriClient().clientId();
    }

    /**
     * Pushes one request and then spends it five ways: once properly, twice over, once after it has
     * been aged past its expiry, once with the expiry edited, and once by somebody else.
     */
    public RequestUriRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        Pushed pushed = probe.push();
        List<RequestUriAttempt> attempts = new ArrayList<>();

        attempts.add(probe.attempt("Used once, by the client that pushed it",
                "The ordinary case: the browser carries a reference and nothing else.",
                pushed.requestUri(), clientId()));
        attempts.add(probe.attempt("The same reference a second time",
                "Nothing about it has expired; it has simply been spent.",
                pushed.requestUri(), clientId()));

        Pushed second = probe.push();
        String aged = age(second.requestUri());
        attempts.add(probe.attempt("One whose expiry has passed",
                "Aged by the page rather than waited out - the stored request is rewritten to the "
                        + "expiry it would have had five minutes ago.",
                aged, clientId()));

        Pushed third = probe.push();
        attempts.add(probe.attempt("The same reference with a later expiry written into it",
                "A client buying itself more time by editing the number in the URI.",
                extend(third.requestUri()), clientId()));
        attempts.add(probe.attempt("Presented by a different client",
                "The reference is not a secret; it is still not transferable.",
                third.requestUri(), properties.client().clientId()));

        log.debug("request_uri run finished; {} of {} attempts produced a code",
                attempts.stream().filter(RequestUriAttempt::gotCode).count(), attempts.size());
        return new RequestUriRun(clientId(), pushed.requestUri(), randomPartOf(pushed.requestUri()),
                expiryOf(pushed.requestUri()), pushed.expiresIn(), List.copyOf(attempts), Instant.now());
    }

    /** Whether the authorization server is still holding the pushed request behind a reference. */
    public boolean stillStored(String requestUri) {
        return authorizationService.findByToken(stateOf(requestUri), STATE_TOKEN_TYPE) != null;
    }

    /**
     * Rewrites the stored request so that it is keyed by an expiry already in the past, and returns
     * the reference that now finds it. Waiting out the real five minutes would demonstrate the same
     * thing and take five minutes.
     */
    private String age(String requestUri) {
        Instant past = Instant.now().minus(Duration.ofMinutes(1));
        return rekey(requestUri, past);
    }

    /**
     * Moves the expiry in the reference a year out without touching what the server stored - which
     * is what a client would try, and the reason the expiry is part of the lookup key.
     */
    private static String extend(String requestUri) {
        Instant later = expiryOf(requestUri).plus(Duration.ofDays(365));
        return PREFIX + randomPartOf(requestUri) + DELIMITER + later.toEpochMilli();
    }

    private String rekey(String requestUri, Instant expiresAt) {
        OAuth2Authorization stored = authorizationService.findByToken(stateOf(requestUri), STATE_TOKEN_TYPE);
        if (stored == null) {
            return requestUri;
        }
        String state = randomPartOf(requestUri) + DELIMITER + expiresAt.toEpochMilli();
        authorizationService.save(OAuth2Authorization.from(stored)
                .attribute(OAuth2ParameterNames.STATE, state)
                .build());
        return PREFIX + state;
    }

    /** The lookup key: everything after the prefix, expiry included. */
    private static String stateOf(String requestUri) {
        return requestUri.substring(PREFIX.length());
    }

    private static String randomPartOf(String requestUri) {
        String state = stateOf(requestUri);
        return state.substring(0, state.lastIndexOf(DELIMITER));
    }

    private static Instant expiryOf(String requestUri) {
        String state = stateOf(requestUri);
        return Instant.ofEpochMilli(
                Long.parseLong(state.substring(state.lastIndexOf(DELIMITER) + DELIMITER.length())));
    }

    private record Pushed(String requestUri, long expiresIn) {
    }

    private record Answer(int status, String location, String body) {
    }

    /** A client with a browser: it authenticates to push, and holds a session to spend. */
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

        /** RFC 9126 section 2: the whole authorization request, posted and authenticated. */
        @SuppressWarnings("unchecked")
        private Pushed push() {
            DemoProperties.Client client = properties.requestUriClient();
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add(OAuth2ParameterNames.RESPONSE_TYPE, "code");
            form.add(OAuth2ParameterNames.CLIENT_ID, client.clientId());
            form.add(OAuth2ParameterNames.SCOPE, String.join(" ", client.scopes()));
            form.add(OAuth2ParameterNames.REDIRECT_URI, base + RequestUriController.CALLBACK_URI);
            form.add(OAuth2ParameterNames.STATE, randomUrlSafe(16));
            form.add("code_challenge", codeChallenge(randomUrlSafe(32)));
            form.add("code_challenge_method", "S256");

            String credentials = client.clientId() + ":" + client.clientSecret();
            Map<String, Object> body = restClient.post()
                    .uri(base + "/oauth2/par")
                    .header(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder()
                            .encodeToString(credentials.getBytes(StandardCharsets.UTF_8)))
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(Map.class);
            if (body == null || body.get("request_uri") == null) {
                throw new IllegalStateException("The pushed authorization request endpoint refused it");
            }
            return new Pushed(String.valueOf(body.get("request_uri")),
                    Long.parseLong(String.valueOf(body.get("expires_in"))));
        }

        /**
         * Spends a reference at the authorization endpoint, exactly as a browser would - client id
         * and request_uri, and nothing else at all.
         */
        private RequestUriAttempt attempt(String label, String description, String requestUri,
                                          String clientId) {
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId)
                    .queryParam("request_uri", requestUri)
                    .build().encode(StandardCharsets.UTF_8).toUriString();

            Answer answer = restClient.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        return new Answer(response.getStatusCode().value(),
                                next == null ? null : URI.create(base).resolve(next).toString(),
                                next == null ? response.bodyTo(String.class) : null);
                    }, false);

            String location = answer.location();
            boolean reachedTheClient = location != null
                    && location.startsWith(base + RequestUriController.CALLBACK_URI);
            boolean gotCode = reachedTheClient && location.contains("code=");
            String error = reachedTheClient
                    ? parameterOf(location, OAuth2ParameterNames.ERROR)
                    : errorInPage(answer.body());
            return new RequestUriAttempt(label, description, answer.status(), gotCode,
                    reachedTheClient, error, stillStored(requestUri));
        }
    }

    /**
     * A refusal that cannot be sent to the client is rendered instead, and the error code is in the
     * page. Reading it back is how the table can say what was wrong rather than only that it failed.
     */
    private static String errorInPage(String body) {
        if (body == null) {
            return null;
        }
        Matcher matcher = Pattern.compile("\\[([a-z_]+)]").matcher(body);
        return matcher.find() ? matcher.group(1) : null;
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
