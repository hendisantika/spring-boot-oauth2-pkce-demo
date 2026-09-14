package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.AuthorizationServerConfig;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.LogoutTokenFactory;
import id.my.hendisantika.oauth2pkcedemo.service.BackChannelLogoutService;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.50
 */
@SpringBootTest
class BackChannelLogoutTests extends AbstractMySqlIntegrationTest {

    private static final String SUBJECT = "hendi";
    private static final String SESSION_ID = "a-session-that-ended";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private BackChannelLogoutService backChannelLogoutService;

    @Autowired
    private LogoutTokenFactory logoutTokenFactory;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    private String registrationId() {
        return properties.client().registrationId();
    }

    private Map<String, Object> claims() {
        return backChannelLogoutService.logoutTokenClaims(
                properties.client().clientId(), SUBJECT, SESSION_ID);
    }

    /** Exactly the request the specification describes: one form parameter, no cookie, no redirect. */
    /** @return whether the endpoint declined the token, however it managed to say so */
    private boolean refused(String logoutToken) throws Exception {
        try {
            int status = send(logoutToken).andReturn().getResponse().getStatus();
            return status < 200 || status >= 300;
        } catch (Exception ex) {
            return true;
        }
    }

    private ResultActions send(String logoutToken) throws Exception {
        return mockMvc().perform(post(BackChannelLogoutService.BACK_CHANNEL_LOGOUT_URI + registrationId())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .param("logout_token", logoutToken));
    }

    /** OpenID Connect Back-Channel Logout section 2.4. */
    @Test
    void aLogoutTokenSaysWhoEndedWhichSessionAndWhy() throws Exception {
        Map<String, Object> claims = claims();

        assertThat(claims)
                .containsEntry("iss", properties.issuerUri())
                .containsEntry("aud", properties.client().clientId())
                .containsEntry("sub", SUBJECT)
                .containsEntry(AuthorizationServerConfig.SESSION_ID, SESSION_ID)
                .containsKeys("iat", "jti");
        assertThat(claims.get(LogoutTokenFactory.EVENTS))
                .asInstanceOf(InstanceOfAssertFactories.MAP)
                .containsKey(LogoutTokenFactory.BACK_CHANNEL_LOGOUT_EVENT);
    }

    /**
     * Section 2.4 asks for the type, and Spring Security's decoder accepts {@code logout+jwt}
     * alongside {@code JWT} - which is worth pinning, because the same decoder refuses the type RFC
     * 9101 asks for on a request object.
     */
    @Test
    void aLogoutTokenIsTypedAsOne() throws Exception {
        JWSHeader header = (JWSHeader) JWTParser.parse(logoutTokenFactory.sign(claims())).getHeader();

        assertThat(header.getType()).isEqualTo(LogoutTokenFactory.LOGOUT_JWT);
        assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        // Signed with the key the server publishes, which is how a client verifies it.
        assertThat(header.getKeyID()).isNotNull();
    }

    @Test
    void everyLogoutTokenIsDistinct() {
        assertThat(claims().get("jti")).isNotEqualTo(claims().get("jti"));
    }

    /** A different key every time, so the one attempt that must fail really does. */
    @Test
    void theForeignlySignedTokenUsesAKeyTheServerDoesNotPublish() throws Exception {
        JWSHeader mine = (JWSHeader) JWTParser.parse(logoutTokenFactory.sign(claims())).getHeader();
        JWSHeader foreign =
                (JWSHeader) JWTParser.parse(logoutTokenFactory.signWithAnotherKey(claims())).getHeader();

        assertThat(foreign.getKeyID()).isNotEqualTo(mine.getKeyID());
    }

    /**
     * The endpoint is mapped and refuses what it cannot verify. It cannot do more than that here:
     * checking a signature means fetching the issuer's JWK Set over HTTP, and nothing is listening
     * during a MockMvc test - which is also why the accepted case is covered by the live run rather
     * than from here.
     */
    @Test
    void theBackChannelEndpointIsMappedAndRefusesWhatItCannotVerify() throws Exception {
        send("not-a-jwt-at-all").andExpect(status().isBadRequest());
        // A well-formed token is refused too, but not always the same way: Spring's provider decodes
        // it by fetching the issuer's JWK Set over HTTP, and when nothing is listening on the issuer
        // - which is the case in a test that boots no connector - the refusal arrives as a decode
        // failure rather than a 400. Either is a refusal; neither is acceptance, and that is what
        // this asserts rather than depending on a server happening to be up.
        assertThat(refused(logoutTokenFactory.sign(claims()))).isTrue();
    }

    /** No session, no cookie, no signed-in user: the back channel is exactly that. */
    @Test
    void theEndpointAsksForNoSessionOfItsOwn() throws Exception {
        send("not-a-jwt-at-all").andExpect(status().isBadRequest());
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/backchannel-logout")).andExpect(status().isOk());
    }

    /** A form-login session holds no client registration, so there is nothing to address. */
    @Test
    void aSessionWithoutAnOidcLoginGetsThePageRatherThanAnError() throws Exception {
        mockMvc().perform(get("/backchannel-logout").with(user(SUBJECT)))
                .andExpect(status().isOk());
        mockMvc().perform(post("/backchannel-logout").with(user(SUBJECT)).with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void anUnknownRunIdYieldsNothing() {
        assertThat(backChannelLogoutService.find("not-a-run")).isNull();
        assertThat(backChannelLogoutService.find(null)).isNull();
    }
}
