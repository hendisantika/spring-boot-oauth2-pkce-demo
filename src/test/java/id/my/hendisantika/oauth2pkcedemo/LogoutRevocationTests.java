package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.RevocationResult;
import id.my.hendisantika.oauth2pkcedemo.security.RevokingLogoutHandler;
import id.my.hendisantika.oauth2pkcedemo.service.LogoutRevocationService;
import id.my.hendisantika.oauth2pkcedemo.service.TokenAdminService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.42
 */
@SpringBootTest
class LogoutRevocationTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private LogoutRevocationService logoutRevocationService;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** Records what it was asked to revoke, in the order it was asked. */
    private static final class RecordingTokenAdminService extends TokenAdminService {

        private final List<String> revoked = new ArrayList<>();

        private RecordingTokenAdminService(DemoProperties properties) {
            super(properties);
        }

        @Override
        public RevocationResult revoke(String token, String tokenTypeHint) {
            this.revoked.add(tokenTypeHint);
            return new RevocationResult(tokenTypeHint, 200, null, Instant.now());
        }
    }

    /** A session of the kind the handler is meant to act on, stored where it would really live. */
    private OAuth2AuthenticationToken storeAuthorizedSession(String principalName, boolean withRefreshToken) {
        ClientRegistration registration = clientRegistrationRepository
                .findByRegistrationId(properties.confidentialClient().registrationId());
        Instant now = Instant.now();
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                "access-" + UUID.randomUUID(), now, now.plusSeconds(300));
        OAuth2RefreshToken refreshToken = withRefreshToken
                ? new OAuth2RefreshToken("refresh-" + UUID.randomUUID(), now) : null;

        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"),
                        Map.of("sub", principalName), "sub"),
                AuthorityUtils.createAuthorityList("ROLE_USER"),
                registration.getRegistrationId());
        authorizedClientService.saveAuthorizedClient(
                new OAuth2AuthorizedClient(registration, principalName, accessToken, refreshToken),
                authentication);
        return authentication;
    }

    private RevokingLogoutHandler handlerRecordingInto(RecordingTokenAdminService tokenAdminService) {
        return new RevokingLogoutHandler(authorizedClientService, tokenAdminService);
    }

    /**
     * The refresh token goes first: revoking it invalidates the authorization it came from, which
     * takes the access token with it whether or not the second call lands.
     */
    @Test
    void bothTokensAreRevokedAndTheRefreshTokenGoesFirst() {
        RecordingTokenAdminService tokenAdminService = new RecordingTokenAdminService(properties);
        OAuth2AuthenticationToken authentication = storeAuthorizedSession("revoke-both", true);

        List<RevocationResult> results = handlerRecordingInto(tokenAdminService).revoke(authentication);

        assertThat(tokenAdminService.revoked)
                .containsExactly(TokenAdminService.REFRESH_TOKEN, TokenAdminService.ACCESS_TOKEN);
        assertThat(results).allMatch(RevocationResult::isAccepted);
    }

    /** Holding credentials that no longer work is its own kind of bug. */
    @Test
    void theClientsOwnCopyOfTheTokensIsRemovedToo() {
        RecordingTokenAdminService tokenAdminService = new RecordingTokenAdminService(properties);
        OAuth2AuthenticationToken authentication = storeAuthorizedSession("remove-copy", true);

        handlerRecordingInto(tokenAdminService).revoke(authentication);

        OAuth2AuthorizedClient remaining = authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(), authentication.getName());
        assertThat(remaining).isNull();
    }

    @Test
    void aSessionWithoutARefreshTokenRevokesOnlyWhatItHas() {
        RecordingTokenAdminService tokenAdminService = new RecordingTokenAdminService(properties);
        OAuth2AuthenticationToken authentication = storeAuthorizedSession("access-only", false);

        handlerRecordingInto(tokenAdminService).revoke(authentication);

        assertThat(tokenAdminService.revoked).containsExactly(TokenAdminService.ACCESS_TOKEN);
    }

    @Test
    void aSessionThatHoldsNoTokensIsLeftAlone() {
        RecordingTokenAdminService tokenAdminService = new RecordingTokenAdminService(properties);
        ClientRegistration registration = clientRegistrationRepository
                .findByRegistrationId(properties.confidentialClient().registrationId());
        OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(
                new DefaultOAuth2User(AuthorityUtils.createAuthorityList("ROLE_USER"),
                        Map.of("sub", "never-authorized"), "sub"),
                AuthorityUtils.createAuthorityList("ROLE_USER"),
                registration.getRegistrationId());

        assertThat(handlerRecordingInto(tokenAdminService).revoke(authentication)).isEmpty();
        assertThat(tokenAdminService.revoked).isEmpty();
    }

    /**
     * {@code /logout} runs for every session, including one that only ever signed in at the form.
     * There is nothing to revoke there, and trying would fail the logout.
     */
    @Test
    void aFormLoginSessionIsNotTouchedByTheHandler() {
        RecordingTokenAdminService tokenAdminService = new RecordingTokenAdminService(properties);

        handlerRecordingInto(tokenAdminService).logout(null, null,
                UsernamePasswordAuthenticationToken.authenticated("hendi", null,
                        AuthorityUtils.createAuthorityList("ROLE_USER")));

        assertThat(tokenAdminService.revoked).isEmpty();
    }

    @Test
    void aRunIdThatWasNeverIssuedYieldsNothing() {
        assertThat(logoutRevocationService.find(UUID.randomUUID().toString())).isNull();
        assertThat(logoutRevocationService.find(null)).isNull();
    }

    /** The page has to be readable after the run, and a run ends signed out. */
    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/logout-revocation")).andExpect(status().isOk());
    }

    /**
     * A session that only signed in at the form holds no tokens and no
     * {@link OAuth2AuthenticationToken}. Asking Spring to resolve one as a controller argument
     * against such a session is a 500 rather than a null, so the page does not ask.
     */
    @Test
    void aFormLoginSessionGetsThePageRatherThanAnError() throws Exception {
        mockMvc().perform(get("/logout-revocation").with(user("hendi")))
                .andExpect(status().isOk());
        mockMvc().perform(post("/logout-revocation").param("revoke", "true").with(user("hendi")).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/logout-revocation"));
    }
}
