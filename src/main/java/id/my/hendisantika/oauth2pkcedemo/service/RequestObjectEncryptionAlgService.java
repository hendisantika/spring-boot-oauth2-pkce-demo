package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.RequestEncryptionAlgAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.RequestEncryptionAlgRun;
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
 * Time: 09.20
 */
@Slf4j
@Service
public class RequestObjectEncryptionAlgService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final JarRequestSigner signer;
    private final RSAKey serverKey;

    public RequestObjectEncryptionAlgService(DemoProperties properties, JarRequestSigner signer,
                                             RSAKey requestDecryptionKey) {
        this.properties = properties;
        this.signer = signer;
        this.serverKey = requestDecryptionKey;
    }

    /** The client that registered nothing, and so registered the default. */
    public DemoProperties.Client defaultAlgClient() {
        return properties.client();
    }

    /** The client that registered RSA-OAEP-512. */
    public DemoProperties.Client oaep512Client() {
        return properties.jarOaep512Client();
    }

    /** The client that registered an algorithm this server does not offer. */
    public DemoProperties.Client rsa15Client() {
        return properties.jarRsa15Client();
    }

    public String serverKeyId() {
        return serverKey.getKeyID();
    }

    /**
     * The same request object wrapped six ways: each client using what it registered, each using
     * the other's algorithm, one using an algorithm this server retired, and one not wrapped at all.
     */
    public RequestEncryptionAlgRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        DemoProperties.Client rsaClient = defaultAlgClient();
        DemoProperties.Client oaep512 = oaep512Client();
        DemoProperties.Client rsa15 = rsa15Client();

        List<RequestEncryptionAlgAttempt> attempts = new ArrayList<>();
        attempts.add(probe.encrypted("Wrapped with what it registered", rsaClient,
                JwtSecuredAuthorizationRequestFilter.DEFAULT_ENCRYPTION_ALG,
                JWEAlgorithm.RSA_OAEP_256));
        attempts.add(probe.encrypted("A stronger hash than it registered", rsaClient,
                JwtSecuredAuthorizationRequestFilter.DEFAULT_ENCRYPTION_ALG,
                JWEAlgorithm.RSA_OAEP_512));
        attempts.add(probe.encrypted("Wrapped with what it registered", oaep512,
                "RSA-OAEP-512", JWEAlgorithm.RSA_OAEP_512));
        attempts.add(probe.encrypted("The algorithm the other client registered", oaep512,
                "RSA-OAEP-512", JWEAlgorithm.RSA_OAEP_256));
        attempts.add(probe.encrypted("Exactly what it registered, and retired here", rsa15,
                "RSA1_5", JWEAlgorithm.RSA1_5));
        attempts.add(probe.unencrypted("Signed only, from a client that registered an algorithm",
                oaep512, "RSA-OAEP-512"));

        log.debug("Request object encryption algorithm run finished; {} of {} accepted",
                attempts.stream().filter(RequestEncryptionAlgAttempt::accepted).count(),
                attempts.size());
        return new RequestEncryptionAlgRun(
                JwtSecuredAuthorizationRequestFilter.DEFAULT_ENCRYPTION_ALG,
                JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS.stream().sorted().toList(),
                List.copyOf(attempts), Instant.now());
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

        /** RFC 9101 section 6.2: signed first, then wrapped for the authorization server. */
        private RequestEncryptionAlgAttempt encrypted(String label, DemoProperties.Client client,
                                                      String registeredAlg, JWEAlgorithm algorithm) {
            String signed = signer.sign(client.clientId(), properties.issuerUri(),
                    requestParameters(client));
            return send(label, client, registeredAlg, algorithm.getName(),
                    signer.encrypt(signed, serverKey.toPublicJWK(), algorithm));
        }

        /** The same object with no wrapping at all, which the registration still permits. */
        private RequestEncryptionAlgAttempt unencrypted(String label, DemoProperties.Client client,
                                                        String registeredAlg) {
            return send(label, client, registeredAlg, RequestEncryptionAlgAttempt.NOT_ENCRYPTED,
                    signer.sign(client.clientId(), properties.issuerUri(), requestParameters(client)));
        }

        private RequestEncryptionAlgAttempt send(String label, DemoProperties.Client client,
                                                 String registeredAlg, String sentAlg,
                                                 String requestObject) {
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
                        return new RequestEncryptionAlgAttempt(label, client.clientId(),
                                registeredAlg, sentAlg, actedOn(location),
                                outcomeOf(location, body));
                    }, false);
        }
    }

    /**
     * Whether the server used the object's parameters. Reaching the consent screen counts: that
     * screen is built from the scopes the object asked for, so getting there means the object was
     * unwrapped, verified and acted on.
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
