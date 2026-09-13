package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.AuthorizationServerConfig;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.BackChannelAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.BackChannelLogoutRun;
import id.my.hendisantika.oauth2pkcedemo.security.LogoutTokenFactory;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.50
 */
@Slf4j
@Service
public class BackChannelLogoutService {

    /** Spring Security's receiving endpoint, one per client registration. */
    public static final String BACK_CHANNEL_LOGOUT_URI = "/logout/connect/back-channel/";

    private static final int RETAINED_RUNS = 16;

    /** A run ends with the session gone, so its result cannot be kept in the session. */
    private final Map<String, BackChannelLogoutRun> runs =
            Collections.synchronizedMap(new LinkedHashMap<>() {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, BackChannelLogoutRun> eldest) {
                    return size() > RETAINED_RUNS;
                }
            });

    private final RestClient restClient;
    private final LogoutTokenFactory logoutTokenFactory;
    private final DemoProperties properties;

    public BackChannelLogoutService(LogoutTokenFactory logoutTokenFactory, DemoProperties properties) {
        this.logoutTokenFactory = logoutTokenFactory;
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    public BackChannelLogoutRun find(String id) {
        return id == null ? null : this.runs.get(id);
    }

    public String backChannelUri(String registrationId) {
        return properties.issuerUri() + BACK_CHANNEL_LOGOUT_URI + registrationId;
    }

    /**
     * OpenID Connect Back-Channel Logout section 2.4. A logout token names the session that ended,
     * is signed by the server that ended it, and is delivered to the client over a connection the
     * browser knows nothing about.
     */
    public Map<String, Object> logoutTokenClaims(String clientId, String subject, String sessionId) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", properties.issuerUri());
        claims.put("aud", clientId);
        claims.put("iat", Instant.now().getEpochSecond());
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("sub", subject);
        claims.put(AuthorizationServerConfig.SESSION_ID, sessionId);
        claims.put(LogoutTokenFactory.EVENTS,
                Map.of(LogoutTokenFactory.BACK_CHANNEL_LOGOUT_EVENT, Map.of()));
        return claims;
    }

    /**
     * Sends six logout tokens to the client's back channel: five that break one rule each, and one
     * that is correct. The correct one goes last, because it ends the session the others are
     * being sent about.
     *
     * @return the id the result was kept under, to be carried through the redirect
     */
    public String run(ClientRegistration registration, String subject, String sessionId,
                      HttpSession session) {
        String clientId = registration.getClientId();
        String uri = BACK_CHANNEL_LOGOUT_URI + registration.getRegistrationId();
        Map<String, Object> claims = logoutTokenClaims(clientId, subject, sessionId);

        List<BackChannelAttempt> attempts = new ArrayList<>();

        Map<String, Object> withoutEvents = new LinkedHashMap<>(claims);
        withoutEvents.remove(LogoutTokenFactory.EVENTS);
        attempts.add(post("Without the events claim",
                "Nothing marks it as a logout token, so it is only a JWT that happens to be signed. "
                        + "Refused - though not the way the specification describes.",
                uri, logoutTokenFactory.sign(withoutEvents)));

        Map<String, Object> withNonce = new LinkedHashMap<>(claims);
        withNonce.put("nonce", UUID.randomUUID().toString());
        attempts.add(post("With a nonce",
                "Section 2.4 says a logout token MUST NOT carry one - it is what tells an ID token "
                        + "apart from this.", uri, logoutTokenFactory.sign(withNonce)));

        Map<String, Object> wrongAudience = new LinkedHashMap<>(claims);
        wrongAudience.put("aud", anotherClientId(clientId));
        attempts.add(post("Addressed to another client",
                "Correct in every other way, and meant for somebody else.", uri,
                logoutTokenFactory.sign(wrongAudience)));

        Map<String, Object> anonymous = new LinkedHashMap<>(claims);
        anonymous.remove("sub");
        anonymous.remove(AuthorizationServerConfig.SESSION_ID);
        attempts.add(post("Naming neither a subject nor a session",
                "A logout token has to say whose session ended.", uri,
                logoutTokenFactory.sign(anonymous)));

        attempts.add(post("Signed by a key the server does not publish",
                "Every claim is right. The client fetches the issuer's JWK Set and the signature "
                        + "does not verify against it.", uri,
                logoutTokenFactory.signWithAnotherKey(claims)));

        String logoutToken = logoutTokenFactory.sign(claims);
        attempts.add(post("A valid logout token",
                "Signed by the issuer, addressed to this client, naming this session.", uri,
                logoutToken));

        boolean invalidated = isInvalidated(session);
        log.debug("Back-channel logout run for [{}] sid={} sessionInvalidated={}",
                clientId, sessionId, invalidated);

        BackChannelLogoutRun run = new BackChannelLogoutRun(registration.getClientName(),
                properties.issuerUri() + uri, logoutToken, claims, attempts, invalidated, Instant.now());
        String id = UUID.randomUUID().toString();
        this.runs.put(id, run);
        return id;
    }

    /**
     * One POST, exactly as the specification describes it: form-encoded, one parameter, no cookies
     * and no redirect.
     */
    @SuppressWarnings("unchecked")
    private BackChannelAttempt post(String label, String description, String uri, String logoutToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("logout_token", logoutToken);

        return this.restClient.post()
                .uri(uri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .body(form)
                .exchange((request, response) -> {
                    int status = response.getStatusCode().value();
                    if (status == 200) {
                        return new BackChannelAttempt(label, description, status,
                                "Accepted. The session it named was ended.");
                    }
                    Map<String, Object> body = response.bodyTo(Map.class);
                    Object reason = body == null ? null : body.get("error_description");
                    if (status >= 500) {
                        // Spring Security means to answer 400 here and cannot: see the page.
                        return new BackChannelAttempt(label, description, status,
                                "Refused, but with a server error rather than the "
                                        + "invalid_request the other refusals give.");
                    }
                    return new BackChannelAttempt(label, description, status,
                            reason == null ? "Refused." : String.valueOf(reason));
                }, false);
    }

    /** Any registered client that is not the one being addressed, so the audience is really wrong. */
    private String anotherClientId(String clientId) {
        return properties.client().clientId().equals(clientId)
                ? properties.confidentialClient().clientId()
                : properties.client().clientId();
    }

    /** The session object is still referenced here; touching it is how it says it is gone. */
    private static boolean isInvalidated(HttpSession session) {
        try {
            session.getCreationTime();
            return false;
        } catch (IllegalStateException ex) {
            return true;
        }
    }
}
