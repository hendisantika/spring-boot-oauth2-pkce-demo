package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.EncryptionMethodCell;
import id.my.hendisantika.oauth2pkcedemo.security.EncryptionMethodGrid;
import id.my.hendisantika.oauth2pkcedemo.security.EncryptionMethodValuesRun;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
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
 * Date: 19/09/26
 * Time: 08.20
 */
@Slf4j
@Service
public class EncryptionMethodValuesService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;
    private final JarRequestSigner signer;
    private final RSAKey serverKey;
    private final RegisteredClientRepository registeredClients;
    private final RestClient restClient;

    public EncryptionMethodValuesService(DemoProperties properties, JarRequestSigner signer,
                                         RSAKey requestDecryptionKey,
                                         RegisteredClientRepository registeredClients) {
        this.properties = properties;
        this.signer = signer;
        this.serverKey = requestDecryptionKey;
        this.registeredClients = registeredClients;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    /** Both lists, read back from the document rather than from the constants behind them. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> advertised() {
        Map<String, Object> document;
        try {
            document = restClient.get()
                    .uri("/.well-known/openid-configuration")
                    .retrieve().body(Map.class);
        } catch (RuntimeException ex) {
            log.debug("Could not read the published lists back: {}", ex.getMessage());
            document = null;
        }
        Map<String, Object> values = new LinkedHashMap<>();
        for (String name : List.of(
                ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED,
                ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED)) {
            Object value = document == null ? null : document.get(name);
            values.put(name, value == null ? "unreachable" : value);
        }
        return values;
    }

    /**
     * Every advertised pair, sent by each of two clients, plus one method the lists leave out. The
     * two lists multiply; a client's registration does not.
     */
    public EncryptionMethodValuesRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        List<String> algs = JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS
                .stream().sorted().toList();
        List<String> encs = JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_METHODS
                .stream().sorted().toList();

        List<EncryptionMethodGrid> grids = new ArrayList<>();
        for (DemoProperties.Client client : List.of(properties.client(), properties.jarGcmClient())) {
            List<EncryptionMethodCell> cells = new ArrayList<>();
            for (String alg : algs) {
                for (String enc : encs) {
                    cells.add(probe.cell(client, alg, enc));
                }
            }
            grids.add(new EncryptionMethodGrid(client.clientId(),
                    registered(client, JwtSecuredAuthorizationRequestFilter.ENCRYPTION_ALG_SETTING),
                    registered(client, JwtSecuredAuthorizationRequestFilter.ENCRYPTION_ENC_SETTING),
                    resolvedEnc(client), List.copyOf(cells)));
        }

        // One method neither list offers, from the client that registered it - so that the refusal
        // is the list speaking rather than a registration mismatch.
        DemoProperties.Client unsupported = properties.jarUnsupportedEncClient();
        EncryptionMethodCell offTheList = probe.cell(unsupported, "RSA-OAEP-256", "A192CBC-HS384");

        log.debug("Encryption method values run finished; {} grids, {} accepted in total",
                grids.size(), grids.stream().mapToLong(EncryptionMethodGrid::accepted).sum());
        Map<String, Object> lists = advertised();
        return new EncryptionMethodValuesRun(
                lists.get(ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED),
                lists.get(ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED),
                algs, encs, List.copyOf(grids), offTheList, unsupported.clientId(), Instant.now());
    }

    /** What the client registered for one setting, or {@code nothing}. */
    private String registered(DemoProperties.Client client, String setting) {
        RegisteredClient registered = registeredClients.findByClientId(client.clientId());
        Object value = registered == null ? null
                : registered.getClientSettings().getSetting(setting);
        return value == null ? EncryptionMethodGrid.NOTHING : String.valueOf(value);
    }

    /**
     * OpenID Connect Registration section 2: "if request_object_encryption_alg is specified, the
     * default request_object_encryption_enc value is A128CBC-HS256". So a client that registered
     * only the algorithm has a method anyway, and this is the one.
     */
    private String resolvedEnc(DemoProperties.Client client) {
        String registered = registered(client,
                JwtSecuredAuthorizationRequestFilter.ENCRYPTION_ENC_SETTING);
        return EncryptionMethodGrid.NOTHING.equals(registered)
                ? JwtSecuredAuthorizationRequestFilter.DEFAULT_ENCRYPTION_ENC
                : registered;
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

    /** A browser with a session, sending one pair at a time. */
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

        private EncryptionMethodCell cell(DemoProperties.Client client, String alg, String enc) {
            String signed = signer.sign(client.clientId(), properties.issuerUri(),
                    requestParameters(client));
            String requestObject = signer.encrypt(signed, serverKey.toPublicJWK(),
                    JWEAlgorithm.parse(alg), EncryptionMethod.parse(enc));
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
                        return new EncryptionMethodCell(alg, enc, actedOn(location),
                                outcomeOf(location, body));
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
