package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectRun;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 23.40
 */
@Slf4j
@Service
public class RequestObjectEncryptionService {

    /**
     * Something in the request worth hiding. A login hint is an identifier for a person, and it
     * travels in the URL like everything else - which is the argument for encrypting the object
     * rather than only signing it.
     */
    public static final String LOGIN_HINT = "hendi@example.com";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    /** Claims an onlooker would find interesting if they could read the request object. */
    private static final List<String> INTERESTING =
            List.of("client_id", "redirect_uri", "scope", "login_hint", "state");

    private final DemoProperties properties;
    private final JarRequestSigner signer;
    private final RSAKey serverKey;

    public RequestObjectEncryptionService(DemoProperties properties, JarRequestSigner signer,
                                          RSAKey requestDecryptionKey) {
        this.properties = properties;
        this.signer = signer;
        this.serverKey = requestDecryptionKey;
    }

    public String clientId() {
        return properties.client().clientId();
    }

    public String serverKeyId() {
        return serverKey.getKeyID();
    }

    /**
     * The same authorization request three ways: signed, signed and encrypted to this server, and
     * encrypted to a key it does not hold.
     */
    public RequestObjectRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        Map<String, String> parameters = requestParameters();
        String signed = signer.sign(clientId(), properties.issuerUri(), parameters);
        String encrypted = signer.encrypt(signed, serverKey.toPublicJWK());
        String misaddressed = signer.encrypt(signed, strangersKey());

        List<RequestObjectAttempt> attempts = new ArrayList<>();
        attempts.add(probe.authorize("Signed, as RFC 9101 requires",
                "Every claim is base64, and the URL carries it past whatever is watching.",
                signed, readableClaims(signed)));
        attempts.add(probe.authorize("Signed, then encrypted to this server",
                "The same object, wrapped for one recipient.", encrypted, List.of()));
        attempts.add(probe.authorize("Encrypted to a key this server does not hold",
                "Well formed, correctly signed inside, and addressed to somebody else.",
                misaddressed, List.of()));

        log.debug("Request object run finished; {} of {} accepted",
                attempts.stream().filter(RequestObjectAttempt::accepted).count(), attempts.size());
        return new RequestObjectRun(clientId(), serverKeyId(), LOGIN_HINT, List.copyOf(attempts),
                Instant.now());
    }

    /** A key belonging to nobody here, to show what being addressed elsewhere looks like. */
    private static RSAKey strangersKey() {
        try {
            return new RSAKeyGenerator(2048).keyID("somebody-elses-key").generate().toPublicJWK();
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to generate the stranger's key", ex);
        }
    }

    /** What is inside the object, which is also what a signed one hands to anyone holding the URL. */
    private static List<String> readableClaims(String signedRequestObject) {
        try {
            var claims = SignedJWT.parse(signedRequestObject).getJWTClaimsSet();
            return INTERESTING.stream().filter(name -> claims.getClaim(name) != null).toList();
        } catch (Exception ex) {
            return List.of();
        }
    }

    private Map<String, String> requestParameters() {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.RESPONSE_TYPE, "code");
        parameters.put(OAuth2ParameterNames.CLIENT_ID, clientId());
        parameters.put(OAuth2ParameterNames.SCOPE,
                String.join(" ", properties.client().scopes()));
        parameters.put(OAuth2ParameterNames.REDIRECT_URI,
                properties.issuerUri() + "/login/oauth2/code/" + properties.client().registrationId());
        parameters.put(OAuth2ParameterNames.STATE, randomUrlSafe(16));
        parameters.put("code_challenge", codeChallenge(randomUrlSafe(32)));
        parameters.put("code_challenge_method", "S256");
        parameters.put("login_hint", LOGIN_HINT);
        return parameters;
    }

    /** A browser with a session, carrying a request object and nothing much else. */
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
         * RFC 9101 section 5: the URL carries a client id and the object, and the object carries
         * everything else.
         */
        private RequestObjectAttempt authorize(String label, String description,
                                               String requestObject, List<String> readable) {
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId())
                    .queryParam("request", requestObject)
                    .build().encode(StandardCharsets.UTF_8).toUriString();

            return restClient.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        String location = next == null ? null
                                : URI.create(base).resolve(next).toString();
                        String body = next == null ? response.bodyTo(String.class) : null;
                        int parts = requestObject.split("\\.").length;
                        return new RequestObjectAttempt(label, description, parts, parts == 5,
                                readable, actedOn(location), outcomeOf(location, body));
                    }, false);
        }
    }

    /**
     * Whether the server used the object's parameters. Reaching the consent screen counts: this
     * client asks for consent, and the screen it shows is built from what the object said.
     */
    private static boolean actedOn(String location) {
        return location != null && !location.contains("error=")
                && (location.contains("code=") || location.contains("/oauth2/consent"));
    }

    /** Where it ended up - and for a refusal, what the refusal said. */
    private static String outcomeOf(String location, String body) {
        if (location != null) {
            if (location.contains("code=")) {
                return "an authorization code";
            }
            if (location.contains("/oauth2/consent")) {
                return "the consent screen, built from the object's own scopes";
            }
            Matcher matcher = Pattern.compile("[?&]error=([^&]*)").matcher(location);
            return matcher.find() ? matcher.group(1) : "somewhere else entirely";
        }
        if (body != null) {
            Matcher described = Pattern.compile("\"error_description\"\\s*:\\s*\"([^\"]+)\"")
                    .matcher(body);
            if (described.find()) {
                return described.group(1);
            }
            Matcher matcher = Pattern.compile("\\[([a-z_]+)]").matcher(body);
            return matcher.find() ? matcher.group(1) : "refused";
        }
        return "refused";
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
