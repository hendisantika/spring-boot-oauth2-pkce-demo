package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.EncryptionAlgValuesAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.EncryptionAlgValuesRun;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
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
 * Date: 18/09/26
 * Time: 20.25
 */
@Slf4j
@Service
public class EncryptionAlgValuesService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final JarRequestSigner signer;
    private final RestClient restClient;

    public EncryptionAlgValuesService(DemoProperties properties, JarRequestSigner signer) {
        this.properties = properties;
        this.signer = signer;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /** The list, read back from the document rather than from the constant behind it. */
    @SuppressWarnings("unchecked")
    public Object advertised() {
        try {
            Map<String, Object> document = restClient.get()
                    .uri("/.well-known/openid-configuration")
                    .retrieve().body(Map.class);
            Object value = document == null ? null : document
                    .get(ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED);
            return value == null ? "unreachable" : value;
        } catch (RuntimeException ex) {
            log.debug("Could not read the published list back: {}", ex.getMessage());
            return "unreachable";
        }
    }

    /** Every key the server publishes, and what each says it is for. */
    public List<Map<String, String>> publishedKeys() {
        List<Map<String, String>> keys = new ArrayList<>();
        for (JWK jwk : published().getKeys()) {
            Map<String, String> described = new LinkedHashMap<>();
            described.put("kty", jwk.getKeyType().getValue());
            described.put("use", jwk.getKeyUse() == null ? null : jwk.getKeyUse().identifier());
            described.put("kid", jwk.getKeyID());
            keys.add(described);
        }
        return keys;
    }

    private JWKSet published() {
        try {
            return JWKSet.parse(restClient.get().uri("/oauth2/jwks").retrieve().body(String.class));
        } catch (Exception ex) {
            throw new IllegalStateException("Could not read the published key set: "
                    + ex.getMessage());
        }
    }

    /**
     * Five request objects. Two of them differ only in which published key they were wrapped to,
     * which is the part the algorithm list says nothing about.
     */
    public EncryptionAlgValuesRun run() {
        JWKSet keys = published();
        RSAKey encryptionKey = firstRsaKey(keys, KeyUse.ENCRYPTION);
        RSAKey signingKey = firstRsaKey(keys, KeyUse.SIGNATURE);

        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        DemoProperties.Client rsa = properties.client();
        DemoProperties.Client oaep512 = properties.jarOaep512Client();
        DemoProperties.Client rsa15 = properties.jarRsa15Client();
        List<String> advertised = JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS
                .stream().sorted().toList();

        List<EncryptionAlgValuesAttempt> attempts = new ArrayList<>();
        attempts.add(probe.encrypted("RSA-OAEP-256, to the encryption key",
                "On the list, what this client registered, and addressed to the key marked for it.",
                rsa, "RSA-OAEP-256", JWEAlgorithm.RSA_OAEP_256, encryptionKey,
                advertised.contains("RSA-OAEP-256")));
        attempts.add(probe.encrypted("The same, to the signing key",
                "Also RSA, also published here, and not the one to use.",
                rsa, "RSA-OAEP-256", JWEAlgorithm.RSA_OAEP_256, signingKey,
                advertised.contains("RSA-OAEP-256")));
        attempts.add(probe.encrypted("RSA-OAEP-512, by the client that registered RSA-OAEP-256",
                "On the list. The list is the server's, not this client's.",
                rsa, "RSA-OAEP-256", JWEAlgorithm.RSA_OAEP_512, encryptionKey,
                advertised.contains("RSA-OAEP-512")));
        attempts.add(probe.encrypted("RSA-OAEP-512, by the client that registered it",
                "Same algorithm, same list, different registration.",
                oaep512, "RSA-OAEP-512", JWEAlgorithm.RSA_OAEP_512, encryptionKey,
                advertised.contains("RSA-OAEP-512")));
        attempts.add(probe.encrypted("RSA1_5, by the client that registered it",
                "A real JWA algorithm, registered by this client, and not on the list.",
                rsa15, "RSA1_5", JWEAlgorithm.RSA1_5, encryptionKey,
                advertised.contains("RSA1_5")));

        log.debug("Encryption algorithm values run finished; {} of {} accepted",
                attempts.stream().filter(EncryptionAlgValuesAttempt::accepted).count(),
                attempts.size());
        return new EncryptionAlgValuesRun(advertised(), publishedKeys(), List.copyOf(attempts),
                Instant.now());
    }

    /** @throws IllegalStateException where the published set has no such key, which would be a bug */
    private static RSAKey firstRsaKey(JWKSet keys, KeyUse use) {
        return keys.getKeys().stream()
                .filter(jwk -> use.equals(jwk.getKeyUse()) && jwk instanceof RSAKey)
                .map(RSAKey.class::cast)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "The published key set has no RSA key marked " + use.identifier()));
    }

    private Map<String, String> requestParameters(DemoProperties.Client client) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.RESPONSE_TYPE, "code");
        parameters.put(OAuth2ParameterNames.CLIENT_ID, client.clientId());
        parameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", client.scopes()));
        parameters.put(OAuth2ParameterNames.REDIRECT_URI,
                properties.issuerUri() + "/login/oauth2/code/" + client.registrationId());
        parameters.put(OAuth2ParameterNames.STATE, randomUrlSafe(16));
        parameters.put("code_challenge", codeChallenge(randomUrlSafe(32)));
        parameters.put("code_challenge_method", "S256");
        return parameters;
    }

    /** A browser with a session, carrying one request object at a time. */
    private final class Probe {

        private final RestClient browser;
        private final String base = properties.issuerUri();

        private Probe() {
            HttpClient httpClient = HttpClient.newBuilder()
                    .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
            this.browser = RestClient.builder()
                    .requestFactory(new JdkClientHttpRequestFactory(httpClient))
                    .build();
        }

        private void signIn(String username, String password) {
            String page = browser.get().uri(base + "/login").retrieve().body(String.class);
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("username", username);
            form.add("password", password);
            form.add("_csrf", csrf(page));
            browser.post()
                    .uri(base + "/login")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .exchange((request, response) -> response.getStatusCode().value(), false);
        }

        private EncryptionAlgValuesAttempt encrypted(String label, String description,
                                                     DemoProperties.Client client,
                                                     String registeredAlg, JWEAlgorithm algorithm,
                                                     RSAKey serverKey, boolean advertised) {
            String signed = signer.sign(client.clientId(), properties.issuerUri(),
                    requestParameters(client));
            String requestObject = signer.encrypt(signed, serverKey.toPublicJWK(), algorithm);
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, client.clientId())
                    .queryParam("request", requestObject)
                    .build().encode(StandardCharsets.UTF_8).toUriString();

            return browser.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        String location = next == null ? null
                                : URI.create(base).resolve(next).toString();
                        String body = next == null ? response.bodyTo(String.class) : null;
                        return new EncryptionAlgValuesAttempt(label, description, client.clientId(),
                                registeredAlg, algorithm.getName(), advertised,
                                serverKey.getKeyUse() == null ? null
                                        : serverKey.getKeyUse().identifier(),
                                serverKey.getKeyID(), actedOn(location), outcomeOf(location, body));
                    }, false);
        }
    }

    /**
     * Whether the server acted on the request. Reaching the consent screen counts: that screen is
     * built from the object's own scopes, so getting there means it was unwrapped and read.
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
                return "the consent screen";
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
