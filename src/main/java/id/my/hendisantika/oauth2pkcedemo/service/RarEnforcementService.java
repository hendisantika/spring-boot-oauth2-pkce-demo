package id.my.hendisantika.oauth2pkcedemo.service;

import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.PaymentApiController;
import id.my.hendisantika.oauth2pkcedemo.controller.RarEnforcementController;
import id.my.hendisantika.oauth2pkcedemo.security.RarEnforcementAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.RarEnforcementRun;
import id.my.hendisantika.oauth2pkcedemo.security.RichAuthorizationRequestValidator;
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
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
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
 * Time: 21.10
 */
@Slf4j
@Service
public class RarEnforcementService {

    /** The creditor the user approves, and one they never did. */
    public static final String APPROVED_IBAN = "DE02100100109307118603";
    public static final String OTHER_IBAN = "DE89370400440532013000";
    public static final String APPROVED_AMOUNT = "25.00";
    public static final String CURRENCY = "EUR";

    /** RFC 9396 section 2: the request the user is asked to approve, in full. */
    public static final String AUTHORIZATION_DETAILS = """
            [{"type":"payment_initiation","actions":["initiate"],\
            "locations":["%s/payments"],\
            "instructedAmount":{"currency":"%s","amount":"%s"},\
            "creditorName":"Merchant Ltd","creditorAccount":{"iban":"%s"}}]""";

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern CSRF = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"");

    private final DemoProperties properties;

    public RarEnforcementService(DemoProperties properties) {
        this.properties = properties;
    }

    public String clientId() {
        return properties.rarClient().clientId();
    }

    public String authorizationDetails() {
        return AUTHORIZATION_DETAILS.formatted(properties.issuerUri(), CURRENCY, APPROVED_AMOUNT,
                APPROVED_IBAN);
    }

    /**
     * Gets one token carrying the approved detail and one carrying none, then holds five payment
     * instructions against them. The grant says which payment was approved, so the resource server
     * can do arithmetic rather than match a category.
     */
    public RarEnforcementRun run() {
        Probe probe = new Probe();
        DemoProperties.DemoUser user = properties.demoUsers().get(0);
        probe.signIn(user.username(), user.password());

        String rich = probe.token(authorizationDetails());
        String plain = probe.token(null);
        List<RarEnforcementAttempt> attempts = new ArrayList<>();

        attempts.add(probe.pay("Exactly what was approved", rich, "the approved token",
                APPROVED_AMOUNT, CURRENCY, APPROVED_IBAN));
        attempts.add(probe.pay("More than was approved", rich, "the approved token",
                "500.00", CURRENCY, APPROVED_IBAN));
        attempts.add(probe.pay("The right amount, somebody else's account", rich, "the approved token",
                APPROVED_AMOUNT, CURRENCY, OTHER_IBAN));
        attempts.add(probe.pay("The approved payment, with an ordinary token", plain,
                "a token with no authorization_details", APPROVED_AMOUNT, CURRENCY, APPROVED_IBAN));
        attempts.add(probe.pay("The approved payment, a second time", rich, "the approved token",
                APPROVED_AMOUNT, CURRENCY, APPROVED_IBAN));

        log.debug("RAR enforcement run finished; {} of {} accepted",
                attempts.stream().filter(RarEnforcementAttempt::isAccepted).count(), attempts.size());
        return new RarEnforcementRun(clientId(), detailsOf(rich), List.copyOf(attempts), Instant.now());
    }

    /** What the authorization server put on the token, which is the only grant that counts. */
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> detailsOf(String accessToken) {
        try {
            Object claim = JWTParser.parse(accessToken).getJWTClaimsSet()
                    .getClaim(RichAuthorizationRequestValidator.AUTHORIZATION_DETAILS);
            return claim instanceof List<?> list
                    ? list.stream().filter(Map.class::isInstance)
                    .map(entry -> (Map<String, Object>) entry).toList()
                    : List.of();
        } catch (Exception ex) {
            return List.of();
        }
    }

    /** A client with a browser: it pushes, walks through the authorization, and redeems. */
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

        /** @param authorizationDetails the RFC 9396 array to ask for, or {@code null} for none */
        @SuppressWarnings("unchecked")
        private String token(String authorizationDetails) {
            String verifier = randomUrlSafe(32);
            String requestUri = push(authorizationDetails, verifier);
            String uri = UriComponentsBuilder.fromUriString(base + "/oauth2/authorize")
                    .queryParam(OAuth2ParameterNames.CLIENT_ID, clientId())
                    .queryParam("request_uri", requestUri)
                    .build().encode(StandardCharsets.UTF_8).toUriString();

            String location = restClient.get()
                    .uri(URI.create(uri))
                    .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                    .exchange((request, response) -> {
                        URI next = response.getHeaders().getLocation();
                        return next == null ? null : URI.create(base).resolve(next).toString();
                    }, false);
            String code = location == null ? null : parameterOf(location, OAuth2ParameterNames.CODE);
            if (code == null) {
                throw new IllegalStateException("The authorization request produced no code");
            }

            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add(OAuth2ParameterNames.GRANT_TYPE, "authorization_code");
            form.add(OAuth2ParameterNames.CODE, code);
            form.add(OAuth2ParameterNames.REDIRECT_URI, base + RarEnforcementController.CALLBACK_URI);
            form.add("code_verifier", verifier);
            Map<String, Object> body = restClient.post()
                    .uri(base + "/oauth2/token")
                    .header(HttpHeaders.AUTHORIZATION, basicAuth())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(Map.class);
            if (body == null || body.get("access_token") == null) {
                throw new IllegalStateException("The token endpoint issued nothing");
            }
            return String.valueOf(body.get("access_token"));
        }

        @SuppressWarnings("unchecked")
        private String push(String authorizationDetails, String verifier) {
            DemoProperties.Client client = properties.rarClient();
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add(OAuth2ParameterNames.RESPONSE_TYPE, "code");
            form.add(OAuth2ParameterNames.CLIENT_ID, client.clientId());
            form.add(OAuth2ParameterNames.SCOPE, String.join(" ", client.scopes()));
            form.add(OAuth2ParameterNames.REDIRECT_URI, base + RarEnforcementController.CALLBACK_URI);
            form.add(OAuth2ParameterNames.STATE, randomUrlSafe(16));
            form.add("code_challenge", codeChallenge(verifier));
            form.add("code_challenge_method", "S256");
            if (authorizationDetails != null) {
                form.add(RichAuthorizationRequestValidator.AUTHORIZATION_DETAILS, authorizationDetails);
            }

            Map<String, Object> body = restClient.post()
                    .uri(base + "/oauth2/par")
                    .header(HttpHeaders.AUTHORIZATION, basicAuth())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(Map.class);
            if (body == null || body.get("request_uri") == null) {
                throw new IllegalStateException("The pushed authorization request was refused");
            }
            return String.valueOf(body.get("request_uri"));
        }

        /** One instruction, held against whatever the token says was approved. */
        @SuppressWarnings("unchecked")
        private RarEnforcementAttempt pay(String label, String accessToken, String tokenDescription,
                                          String amount, String currency, String iban) {
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("amount", amount);
            form.add("currency", currency);
            form.add("creditor_iban", iban);

            return restClient.post()
                    .uri(base + PaymentApiController.PAYMENTS_URI)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .exchange((request, response) -> {
                        Map<String, Object> body = response.bodyTo(Map.class);
                        String reason = body == null ? null : String.valueOf(body.get("reason"));
                        return new RarEnforcementAttempt(label,
                                amount + " " + currency + " to " + iban, tokenDescription,
                                response.getStatusCode().value(), reason);
                    }, false);
        }

        private String basicAuth() {
            DemoProperties.Client client = properties.rarClient();
            String credentials = client.clientId() + ":" + client.clientSecret();
            return "Basic " + Base64.getEncoder()
                    .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
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
