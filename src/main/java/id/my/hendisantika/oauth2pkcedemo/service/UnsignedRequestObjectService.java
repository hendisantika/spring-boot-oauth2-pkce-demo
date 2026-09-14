package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jose.jwk.RSAKey;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import id.my.hendisantika.oauth2pkcedemo.security.UnsignedRequestAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.UnsignedRequestRun;
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
 * Date: 16/09/26
 * Time: 14.30
 */
@Slf4j
@Service
public class UnsignedRequestObjectService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final JarRequestSigner signer;
    private final RSAKey serverKey;

    public UnsignedRequestObjectService(DemoProperties properties, JarRequestSigner signer,
                                        RSAKey requestDecryptionKey) {
        this.properties = properties;
        this.signer = signer;
        this.serverKey = requestDecryptionKey;
    }

    /** The client that registered {@code none}. */
    public DemoProperties.Client noneClient() {
        return properties.jarNoneClient();
    }

    /** The client that registered {@code none} and the defence against it in the same breath. */
    public DemoProperties.Client strictClient() {
        return properties.jarNoneStrictClient();
    }

    /** The client that registered nothing, and so is held to RS256. */
    public DemoProperties.Client signingClient() {
        return properties.client();
    }

    public boolean serverRequiresSignedRequestObjects() {
        return ServerMetadataCustomizer.REQUIRE_SIGNED_REQUEST_OBJECT;
    }

    /**
     * Six request objects, of which five are unsigned. What separates the accepted ones from the
     * refused is never the cryptography - there is none - but what each client registered and
     * whether the object still says who sent it.
     */
    public UnsignedRequestRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        DemoProperties.Client none = noneClient();
        List<UnsignedRequestAttempt> attempts = new ArrayList<>();

        attempts.add(probe.unsigned("Unsigned, as it registered", none,
                "No signature to check, and this server checks none.", false, false, Map.of()));
        attempts.add(probe.signed("Signed, by a client that registered none", none,
                "A better request object than the registration promised, and refused for it."));
        attempts.add(probe.unsigned("Unsigned, by a client that registered RS256",
                signingClient(), "The ordinary case: a client held to a signature it did not send.",
                false, false, Map.of()));
        attempts.add(probe.unsigned("Unsigned, with the defence registered", strictClient(),
                "RFC 9101 section 10.5, as client metadata, against the same client's own none.",
                true, false, Map.of()));
        attempts.add(probe.unsigned("Unsigned, encrypted to this server", none,
                "Confidential, and authenticated by nothing at all.", false, true, Map.of()));
        attempts.add(probe.unsigned("Unsigned, naming another client", none,
                "The client_id claim says one thing and the request says another.", false, false,
                Map.of(OAuth2ParameterNames.CLIENT_ID, signingClient().clientId())));

        log.debug("Unsigned request object run finished; {} of {} accepted",
                attempts.stream().filter(UnsignedRequestAttempt::accepted).count(), attempts.size());
        return new UnsignedRequestRun(serverRequiresSignedRequestObjects(),
                JwtSecuredAuthorizationRequestFilter.SUPPORTED_SIGNING_ALGS.stream().sorted().toList(),
                List.copyOf(attempts), Instant.now());
    }

    private Map<String, String> requestParameters(DemoProperties.Client client,
                                                  Map<String, String> overrides) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put(OAuth2ParameterNames.RESPONSE_TYPE, "code");
        parameters.put(OAuth2ParameterNames.CLIENT_ID, client.clientId());
        parameters.put(OAuth2ParameterNames.SCOPE, String.join(" ", client.scopes()));
        parameters.put(OAuth2ParameterNames.REDIRECT_URI,
                properties.issuerUri() + "/login/oauth2/code/" + client.registrationId());
        parameters.put(OAuth2ParameterNames.STATE, randomUrlSafe(16));
        parameters.put("code_challenge", codeChallenge(randomUrlSafe(32)));
        parameters.put("code_challenge_method", "S256");
        parameters.putAll(overrides);
        return parameters;
    }

    /** A browser with a session, carrying one request object at a time. */
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
         * @param overrides claims to write into the object that differ from what the request says
         */
        private UnsignedRequestAttempt unsigned(String label, DemoProperties.Client client,
                                                String description, boolean requireSigned,
                                                boolean encrypt, Map<String, String> overrides) {
            String plain = signer.unsigned(client.clientId(), properties.issuerUri(),
                    requestParameters(client, overrides));
            String requestObject = encrypt ? signer.encrypt(plain, serverKey.toPublicJWK()) : plain;

            return send(label, description, client, requireSigned, encrypt,
                    JwtSecuredAuthorizationRequestFilter.NO_SIGNATURE, requestObject);
        }

        private UnsignedRequestAttempt signed(String label, DemoProperties.Client client,
                                              String description) {
            String requestObject = signer.sign(client.clientId(), properties.issuerUri(),
                    requestParameters(client, Map.of()));
            return send(label, description, client, false, false, "RS256", requestObject);
        }

        private UnsignedRequestAttempt send(String label, String description,
                                            DemoProperties.Client client, boolean requireSigned,
                                            boolean encrypted, String sentAlg, String requestObject) {
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, client.clientId())
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
                        return new UnsignedRequestAttempt(label, description, client.clientId(),
                                registeredAlgOf(client), sentAlg, requireSigned, encrypted,
                                actedOn(location), outcomeOf(location, body));
                    }, false);
        }
    }

    /** What the page shows in the registration column, read from the same constants the filter uses. */
    private String registeredAlgOf(DemoProperties.Client client) {
        return client.clientId().equals(signingClient().clientId())
                ? JwtSecuredAuthorizationRequestFilter.DEFAULT_SIGNING_ALG
                : JwtSecuredAuthorizationRequestFilter.NO_SIGNATURE;
    }

    /**
     * Whether the server used the object's parameters. Reaching the consent screen counts: that
     * screen is built from the scopes the object asked for, so getting there means the object was
     * accepted and acted on.
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
