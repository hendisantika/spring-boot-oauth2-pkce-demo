package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.FreshnessController;
import id.my.hendisantika.oauth2pkcedemo.security.AuthenticationFreshness;
import id.my.hendisantika.oauth2pkcedemo.security.FreshnessAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.FreshnessRun;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
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
 * Time: 15.10
 */
@Slf4j
@Service
public class FreshnessService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF =
            Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;

    public FreshnessService(DemoProperties properties) {
        this.properties = properties;
    }

    public String clientId() {
        return properties.freshnessClient().clientId();
    }

    /**
     * Signs a session in and then asks the authorization endpoint the same question three ways. The
     * probe holds its own cookies deliberately: in this demo the client and the authorization server
     * share one session, so a second authorization request from the page's own session restarts the
     * login whatever it carries - which would answer every row the same way and prove nothing.
     */
    public FreshnessRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        Instant signedInAt = Instant.now();
        probe.signIn(user.username(), user.password());

        List<FreshnessAttempt> attempts = new ArrayList<>();
        Instant authTime = null;

        // Generous: the session is seconds old, so nothing should happen, and nothing should.
        FreshnessAttempt first = probe.authorize("Asked for an hour's grace",
                AuthenticationFreshness.MAX_AGE, "3600", signedInAt, authTime);
        attempts.add(first);
        authTime = first.authTime();

        // auth_time has one-second resolution, and the whole run takes less than that. Waiting
        // makes the difference between "the same authentication" and "a new one" visible at all.
        pause();

        // Nothing is fresh enough for zero, which is how a client says "prove it again now".
        FreshnessAttempt second = probe.authorize("Asked for no grace at all",
                AuthenticationFreshness.MAX_AGE, "0", signedInAt, authTime);
        attempts.add(second);
        authTime = second.authTime() == null ? authTime : second.authTime();

        pause();

        // The blunt instrument, which this server validates and then ignores.
        attempts.add(probe.authorize("Asked to be put through the login again",
                "prompt", "login", signedInAt, authTime));

        log.debug("Freshness run finished; {} of 2 asks were honoured", attempts.stream()
                .filter(FreshnessAttempt::sentBackThroughLogin).count());
        return new FreshnessRun(clientId(), user.username(), signedInAt, List.copyOf(attempts),
                Instant.now());
    }

    /** Long enough for the clock to tick, since auth_time is a number of whole seconds. */
    private static void pause() {
        try {
            Thread.sleep(Duration.ofMillis(1200));
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    /** One browser's worth of cookies, and the handful of requests a login and a redemption take. */
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

        /**
         * Sends one authorization request and follows wherever it leads, signing in again if the
         * endpoint asks. Being asked to sign in again <em>is</em> the answer: it is what OpenID
         * Connect Core 3.1.2.1 means by actively re-authenticating the end user.
         */
        private FreshnessAttempt authorize(String label, String name, String value,
                                           Instant signedInAt, Instant previousAuthTime) {
            String verifier = randomUrlSafe(32);
            String parameter = name + "=" + value;
            // Built and encoded once: RestClient encodes a String uri again, which turned the space
            // between the two scopes into a literal %2520 and was answered with invalid_scope.
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId())
                    .queryParam(OAuth2ParameterNames.SCOPE, "openid profile")
                    .queryParam(OAuth2ParameterNames.REDIRECT_URI, base + FreshnessController.CALLBACK_URI)
                    .queryParam(OAuth2ParameterNames.STATE, randomUrlSafe(16))
                    .queryParam("code_challenge", codeChallenge(verifier))
                    .queryParam("code_challenge_method", "S256")
                    .queryParam(name, value)
                    .build().encode(StandardCharsets.UTF_8).toUriString();

            long age = Duration.between(signedInAt, Instant.now()).toSeconds();
            boolean signedInAgain = false;
            String location = uri;
            String code = null;
            String error = null;
            for (int hop = 0; hop < 8 && location != null; hop++) {
                if (location.startsWith(base + FreshnessController.CALLBACK_URI)) {
                    code = parameterOf(location, "code");
                    error = parameterOf(location, "error");
                    break;
                }
                if (location.startsWith(base + "/login")) {
                    signedInAgain = true;
                    DemoProperties.DemoUser user = properties.demoUsers().get(0);
                    signIn(user.username(), user.password());
                    location = uri;
                    continue;
                }
                location = redirectOf(location);
            }

            Instant authTime = code == null ? null : authTimeOf(redeem(code, verifier));
            String outcome;
            if (code == null) {
                outcome = error == null
                        ? "The flow did not finish, so there is nothing to read."
                        : "The authorization endpoint refused it: " + error;
            } else if (signedInAgain) {
                outcome = "Sent back through the login, and the new token says so.";
            } else {
                outcome = "Issued a code straight away; the session was reused as it stood.";
            }
            return new FreshnessAttempt(label, parameter, age, signedInAgain, authTime,
                    previousAuthTime, outcome);
        }

        private String redirectOf(String uri) {
            return restClient.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        return next == null ? null : URI.create(base).resolve(next).toString();
                    }, false);
        }

        @SuppressWarnings("unchecked")
        private String redeem(String code, String verifier) {
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "authorization_code");
            form.add("code", code);
            form.add("redirect_uri", base + FreshnessController.CALLBACK_URI);
            form.add("client_id", clientId());
            form.add("code_verifier", verifier);
            Map<String, Object> body = restClient.post()
                    .uri(base + "/oauth2/token")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .exchange((request, response) -> response.bodyTo(Map.class), false);
            return body == null ? null : (String) body.get("id_token");
        }
    }

    /** The claim the whole page is about, read straight off the token that came back. */
    private static Instant authTimeOf(String idToken) {
        try {
            // Nimbus only converts the claims JWT itself registers as dates - exp, iat, nbf - so
            // auth_time arrives as a plain number of seconds.
            Object authTime = JWTParser.parse(idToken).getJWTClaimsSet().getClaim("auth_time");
            if (authTime instanceof Number seconds) {
                return Instant.ofEpochSecond(seconds.longValue());
            }
            return authTime instanceof java.util.Date date ? date.toInstant() : null;
        } catch (Exception ex) {
            log.debug("Unable to read auth_time: {}", ex.getMessage());
            return null;
        }
    }

    private static String csrf(String page) {
        Matcher matcher = CSRF.matcher(page == null ? "" : page);
        return matcher.find() ? matcher.group(1) : "";
    }

    private static String parameterOf(String uri, String name) {
        Matcher matcher = Pattern.compile("[?&]" + name + "=([^&]+)").matcher(uri);
        return matcher.find() ? matcher.group(1) : null;
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
