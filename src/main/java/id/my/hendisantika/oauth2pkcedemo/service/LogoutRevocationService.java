package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.IntrospectionResult;
import id.my.hendisantika.oauth2pkcedemo.security.LogoutRevocationRun;
import id.my.hendisantika.oauth2pkcedemo.security.LogoutStep;
import id.my.hendisantika.oauth2pkcedemo.security.RevocationResult;
import id.my.hendisantika.oauth2pkcedemo.security.RevokingLogoutHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
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
 * Time: 19.42
 */
@Slf4j
@Service
public class LogoutRevocationService {

    /** How many runs are kept. They are only here to survive the redirect that follows a logout. */
    private static final int RETAINED_RUNS = 16;

    /**
     * The results have to outlive the session, because ending the session is what the run does. A
     * small bounded map keyed by an id carried in the URL does that without inventing storage.
     */
    private final Map<String, LogoutRevocationRun> runs =
            Collections.synchronizedMap(new LinkedHashMap<>() {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, LogoutRevocationRun> eldest) {
                    return size() > RETAINED_RUNS;
                }
            });

    private final SecurityContextLogoutHandler securityContextLogoutHandler =
            new SecurityContextLogoutHandler();

    private final RestClient restClient;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final RevokingLogoutHandler revokingLogoutHandler;
    private final TokenAdminService tokenAdminService;
    private final DemoProperties properties;

    public LogoutRevocationService(OAuth2AuthorizedClientService authorizedClientService,
                                   RevokingLogoutHandler revokingLogoutHandler,
                                   TokenAdminService tokenAdminService,
                                   DemoProperties properties) {
        this.authorizedClientService = authorizedClientService;
        this.revokingLogoutHandler = revokingLogoutHandler;
        this.tokenAdminService = tokenAdminService;
        this.properties = properties;
        this.restClient = RestClient.create(properties.issuerUri());
    }

    public LogoutRevocationRun find(String id) {
        return id == null ? null : this.runs.get(id);
    }

    /**
     * Signs the user out for real and looks at what became of their tokens. Running it twice, once
     * each way, is the whole demonstration: the only difference between the two is whether anything
     * told the authorization server.
     *
     * @param revoke whether the logout revokes the tokens as RFC 7009 allows, or only ends the
     *               session as both of this application's logouts did before
     * @return the id under which the result was kept, to be carried through the redirect
     */
    public String run(OAuth2AuthenticationToken authentication, boolean revoke,
                      HttpServletRequest request, HttpServletResponse response) {
        OAuth2AuthorizedClient authorizedClient = this.authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(), authentication.getName());
        String accessToken = authorizedClient.getAccessToken().getTokenValue();
        String refreshToken = authorizedClient.getRefreshToken() == null
                ? null : authorizedClient.getRefreshToken().getTokenValue();
        String clientName = authorizedClient.getClientRegistration().getClientName();

        List<LogoutStep> steps = new ArrayList<>();
        steps.add(introspected("Before anything", "The session's access token, as issued.",
                accessToken, TokenAdminService.ACCESS_TOKEN));
        if (refreshToken != null) {
            steps.add(introspected("Before anything", "And the refresh token beside it.",
                    refreshToken, TokenAdminService.REFRESH_TOKEN));
        }

        if (revoke) {
            List<RevocationResult> revocations = this.revokingLogoutHandler.revoke(authentication);
            steps.add(LogoutStep.of("Revoke, then log out",
                    "RFC 7009, one call per token, before the session is touched.",
                    revocations.size() + " token(s) revoked, all answered "
                            + revocations.stream().map(RevocationResult::statusCode).distinct().toList(),
                    false));
        }

        // Exactly what Spring Security's logout does, and exactly what Spring Authorization Server's
        // RP-initiated logout does: clear the context, invalidate the session. Nothing else.
        this.securityContextLogoutHandler.logout(request, response, authentication);
        steps.add(LogoutStep.of("Log out",
                "SecurityContextLogoutHandler: clear the context, invalidate the session.",
                "The user is signed out. The session is gone.", false));

        IntrospectionResult afterAccess =
                this.tokenAdminService.introspect(accessToken, TokenAdminService.ACCESS_TOKEN);
        steps.add(LogoutStep.of("Introspect the access token",
                "The same token value, after the session it came from has ended.",
                afterAccess.active() ? "active = true" : "active = false", afterAccess.active()));

        boolean minted = false;
        if (refreshToken != null) {
            IntrospectionResult afterRefresh =
                    this.tokenAdminService.introspect(refreshToken, TokenAdminService.REFRESH_TOKEN);
            steps.add(LogoutStep.of("Introspect the refresh token", "And the refresh token.",
                    afterRefresh.active() ? "active = true" : "active = false", afterRefresh.active()));

            String newAccessToken = refresh(refreshToken);
            minted = newAccessToken != null;
            steps.add(LogoutStep.of("Use the refresh token",
                    "grant_type=refresh_token, sent after the user signed out.",
                    minted
                            ? "A new access token was issued, minutes of validity ahead of it."
                            : "invalid_grant. There is nothing left to refresh.",
                    minted));
        }

        LogoutRevocationRun run = new LogoutRevocationRun(revoke, clientName, steps,
                afterAccess.active(), minted, Instant.now());
        String id = newRunId();
        this.runs.put(id, run);
        log.debug("Logout run {}: revoke={} accessSurvived={} refreshWorked={}",
                id, revoke, afterAccess.active(), minted);
        return id;
    }

    /** The plainest possible test of whether a refresh token still works. */
    @SuppressWarnings("unchecked")
    private String refresh(String refreshToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue());
        form.add(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken);

        return this.restClient.post()
                .uri("/oauth2/token")
                .header("Authorization", basicAuthHeader())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .exchange((request, response) -> {
                    if (!response.getStatusCode().is2xxSuccessful()) {
                        return null;
                    }
                    Map<String, Object> body = response.bodyTo(Map.class);
                    return body == null ? null : String.valueOf(body.get("access_token"));
                }, false);
    }

    private LogoutStep introspected(String label, String description, String token, String hint) {
        IntrospectionResult result = this.tokenAdminService.introspect(token, hint);
        return LogoutStep.of(label + ": " + hint.replace('_', ' '), description,
                result.active() ? "active = true" : "active = false", result.active());
    }

    private String basicAuthHeader() {
        DemoProperties.Client client = properties.confidentialClient();
        String credentials = client.clientId() + ":" + client.clientSecret();
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    private static String newRunId() {
        return UUID.randomUUID().toString();
    }
}
