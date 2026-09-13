package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.SilentAuthController;
import id.my.hendisantika.oauth2pkcedemo.security.SilentAuthAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.SilentAuthRun;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 17.20
 */
@Slf4j
@Service
public class SilentAuthService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;

    public SilentAuthService(DemoProperties properties,
                             RegisteredClientRepository registeredClientRepository,
                             OAuth2AuthorizationConsentService authorizationConsentService) {
        this.properties = properties;
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationConsentService = authorizationConsentService;
    }

    public String clientId() {
        return properties.silentClient().clientId();
    }

    /**
     * Walks a client through the whole life of {@code prompt=none}: before there is a session,
     * after there is one but before the user has agreed to anything, after they have, and the two
     * ways of asking for something the parameter cannot deliver.
     */
    public SilentAuthRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        forgetPreviousConsent(user.username());
        List<SilentAuthAttempt> attempts = new ArrayList<>();

        attempts.add(probe.authorize("Before there is a session at all",
                "prompt=none", "prompt", "none"));

        probe.signIn(user.username(), user.password());
        attempts.add(probe.authorize("Signed in, but the user has never agreed",
                "prompt=none", "prompt", "none"));

        probe.consentInTheOpen();
        attempts.add(probe.authorize("Signed in, and the user agreed once already",
                "prompt=none", "prompt", "none"));

        attempts.add(probe.authorize("Asking not to be interrupted and to be interrupted",
                "prompt=none login", "prompt", "none login"));
        attempts.add(probe.authorize("Silent, but insisting the session be fresh",
                "prompt=none&max_age=0", "prompt", "none", "max_age", "0"));

        log.debug("Silent authentication run finished with {} attempts", attempts.size());
        return new SilentAuthRun(clientId(), List.copyOf(attempts), Instant.now());
    }

    /**
     * A consent, once given, is remembered - so a second run would find the user had already agreed
     * and the middle question would answer itself. The run starts by forgetting it, which is the
     * only way that row stays true after the first time.
     */
    private void forgetPreviousConsent(String username) {
        RegisteredClient client = registeredClientRepository.findByClientId(clientId());
        if (client == null) {
            return;
        }
        OAuth2AuthorizationConsent consent =
                authorizationConsentService.findById(client.getId(), username);
        if (consent != null) {
            authorizationConsentService.remove(consent);
            log.debug("Forgot the stored consent for {}", clientId());
        }
    }

    /** One browser's worth of cookies, following nothing it is not told to. */
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
         * The one interaction the whole page turns on: an ordinary authorization request, a consent
         * screen, and a user saying yes to it. Everything silent afterwards depends on this having
         * happened once in the open.
         */
        private void consentInTheOpen() {
            String verifier = randomUrlSafe(32);
            String location = redirectOf(authorizationUri(verifier, randomUrlSafe(16)));
            if (location == null || !location.contains("/oauth2/consent")) {
                log.debug("No consent screen appeared; the run continues with what there is");
                return;
            }
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add(OAuth2ParameterNames.CLIENT_ID, clientId());
            form.add(OAuth2ParameterNames.STATE, parameterOf(location, OAuth2ParameterNames.STATE));
            properties.silentClient().scopes().forEach(scope -> form.add(OAuth2ParameterNames.SCOPE, scope));
            restClient.post()
                    .uri(base + "/oauth2/authorize")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .exchange((request, response) -> response.getStatusCode().value(), false);
        }

        /**
         * One authorization request, and whatever came straight back. Nothing is followed: where the
         * first response points <em>is</em> the answer, and a redirect to a page of this
         * application's own is exactly the failure {@code prompt=none} is meant to prevent.
         */
        private SilentAuthAttempt authorize(String label, String shown, String... parameters) {
            String state = randomUrlSafe(16);
            UriComponentsBuilder uri = authorizationUriBuilder(randomUrlSafe(32), state);
            for (int i = 0; i < parameters.length; i += 2) {
                uri.queryParam(parameters[i], parameters[i + 1]);
            }
            String location = redirectOf(uri.build().encode(StandardCharsets.UTF_8).toUriString());

            boolean toTheClient = location != null
                    && location.startsWith(base + SilentAuthController.CALLBACK_URI);
            String code = toTheClient ? parameterOf(location, OAuth2ParameterNames.CODE) : null;
            String error = toTheClient ? parameterOf(location, OAuth2ParameterNames.ERROR) : null;
            String description = toTheClient
                    ? parameterOf(location, OAuth2ParameterNames.ERROR_DESCRIPTION) : null;

            return new SilentAuthAttempt(label, shown, state, error, description,
                    code != null, !toTheClient);
        }

        private String authorizationUri(String verifier, String state) {
            return authorizationUriBuilder(verifier, state).build()
                    .encode(StandardCharsets.UTF_8).toUriString();
        }

        private UriComponentsBuilder authorizationUriBuilder(String verifier, String state) {
            return UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.RESPONSE_TYPE, "code")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId())
                    .queryParam(OAuth2ParameterNames.SCOPE,
                            String.join(" ", properties.silentClient().scopes()))
                    .queryParam(OAuth2ParameterNames.REDIRECT_URI,
                            base + SilentAuthController.CALLBACK_URI)
                    .queryParam(OAuth2ParameterNames.STATE, state)
                    .queryParam("code_challenge", codeChallenge(verifier))
                    .queryParam("code_challenge_method", "S256");
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
