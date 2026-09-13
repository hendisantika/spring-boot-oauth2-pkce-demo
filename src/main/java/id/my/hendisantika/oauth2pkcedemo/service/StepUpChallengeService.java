package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.StrongResourceController;
import id.my.hendisantika.oauth2pkcedemo.security.ResourceCallAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.StepUpChallenge;
import id.my.hendisantika.oauth2pkcedemo.security.StepUpChallengeRun;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 13.40
 */
@Slf4j
@Service
public class StepUpChallengeService {

    /**
     * What the client has seen so far, per user - deliberately not in the session. Acting on the
     * challenge means starting a new authorization request, and this demo's
     * {@code RestartOAuth2LoginFilter} invalidates the session when it does. That is not an
     * inconvenience to work around: a challenge is the client's own state, and a real client would
     * not keep it anywhere the authorization server's login could throw away either.
     */
    private final Map<String, StepUpChallengeRun> runs = new ConcurrentHashMap<>();

    private final RestClient restClient;
    private final String transferUri;

    public StepUpChallengeService(DemoProperties properties) {
        this.restClient = RestClient.create(properties.issuerUri());
        this.transferUri = properties.issuerUri() + StrongResourceController.TRANSFER_URI;
    }

    public String transferUri() {
        return transferUri;
    }

    public StepUpChallengeRun runFor(String username) {
        return runs.getOrDefault(username, StepUpChallengeRun.empty());
    }

    public void reset(String username) {
        runs.remove(username);
    }

    /**
     * Calls the operation and keeps the result where the next authorization cannot erase it. A loop
     * that already closed is not continued: the next call starts a fresh one, so the page shows one
     * story at a time.
     */
    public StepUpChallengeRun record(String username, String label, String accessToken, String tokenAcr) {
        return runs.compute(username, (key, existing) ->
                (existing == null || existing.succeeded() ? StepUpChallengeRun.empty() : existing)
                        .with(call(label, accessToken, tokenAcr)));
    }

    /**
     * Calls the protected operation with whatever token the session is holding, and keeps the
     * {@code WWW-Authenticate} header whether or not it liked the answer. The header is the whole
     * point: without reading it a client knows only that something was refused.
     */
    private ResourceCallAttempt call(String label, String accessToken, String tokenAcr) {
        return restClient.post()
                .uri(StrongResourceController.TRANSFER_URI)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .exchange((request, response) -> {
                    int status = response.getStatusCode().value();
                    String body = response.bodyTo(String.class);
                    StepUpChallenge challenge = StepUpChallenge.parse(
                            response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE));
                    log.debug("Transfer call [{}] -> {} with challenge {}", label, status,
                            challenge == null ? "none" : challenge.error());
                    return new ResourceCallAttempt(label, tokenAcr, status,
                            body == null || body.isBlank() ? "(empty)" : body, challenge, Instant.now());
                }, false);
    }
}
