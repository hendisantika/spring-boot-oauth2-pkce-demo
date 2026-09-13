package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.ClientFrontChannelLogoutController;
import id.my.hendisantika.oauth2pkcedemo.security.FrontChannelLogoutTarget;
import id.my.hendisantika.oauth2pkcedemo.service.FrontChannelLogoutService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 20.09
 */
@SpringBootTest
class FrontChannelLogoutTests extends AbstractMySqlIntegrationTest {

    private static final String SESSION_ID = "the-session-that-ended";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private FrontChannelLogoutService frontChannelLogoutService;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    private String logoutUri(String registrationId) {
        return ClientFrontChannelLogoutController.LOGOUT_URI + registrationId;
    }

    /**
     * OpenID Connect Front-Channel Logout section 2: a client that asked for the session to be named
     * gets iss and sid, and one that did not gets a bare URI.
     */
    @Test
    void onlyTheClientThatAskedForItIsToldWhichSession() {
        List<FrontChannelLogoutTarget> targets = frontChannelLogoutService.targets(SESSION_ID);

        assertThat(targets).hasSize(2);
        FrontChannelLogoutTarget named = targets.stream()
                .filter(FrontChannelLogoutTarget::sessionRequired).findFirst().orElseThrow();
        FrontChannelLogoutTarget bare = targets.stream()
                .filter(target -> !target.sessionRequired()).findFirst().orElseThrow();

        assertThat(named.uri())
                .contains(ClientFrontChannelLogoutController.ISSUER + "=")
                .contains(ClientFrontChannelLogoutController.SESSION_ID + "=" + SESSION_ID);
        assertThat(bare.uri()).doesNotContain("?");
    }

    /** One iframe per client, and nothing else in it: no token, nothing signed. */
    @Test
    void theDocumentIsIframesAndNothingElse() {
        String document = frontChannelLogoutService.document(
                frontChannelLogoutService.targets(SESSION_ID));

        assertThat(document).contains("<iframe").contains("</html>");
        assertThat(document.split("<iframe", -1)).hasSize(3);
        assertThat(document).doesNotContain("logout_token").doesNotContain("<script");
    }

    /**
     * The whole finding in one assertion: a request the client could do nothing with is answered
     * exactly like one that worked, because there is nobody listening for the difference.
     */
    @Test
    void aRequestWithNoSessionIsAnsweredJustLikeOneThatWorked() throws Exception {
        mockMvc().perform(get(logoutUri(properties.client().registrationId()))
                        .param(ClientFrontChannelLogoutController.ISSUER, properties.issuerUri())
                        .param(ClientFrontChannelLogoutController.SESSION_ID, SESSION_ID))
                .andExpect(status().isOk())
                .andExpect(content().string("no session to end"));
    }

    @Test
    void aClientNobodyRegisteredIsAnsweredTheSameWay() throws Exception {
        mockMvc().perform(get(logoutUri("no-such-client")))
                .andExpect(status().isOk())
                .andExpect(content().string("no session to end"));
    }

    /** A form login is not an OIDC session, so there is nothing for this endpoint to end. */
    @Test
    void aSessionThatDidNotComeFromTheProviderIsLeftAlone() throws Exception {
        mockMvc().perform(get(logoutUri(properties.client().registrationId())).with(user("hendi")))
                .andExpect(status().isOk())
                .andExpect(content().string("no session to end"));
    }

    /**
     * The iframes are same-origin here, and the default DENY would have stopped the browser loading
     * any of them.
     */
    @Test
    void thePagesMayBeFramedBySomethingOnTheSameOrigin() throws Exception {
        mockMvc().perform(get("/frontchannel-logout"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Frame-Options", "SAMEORIGIN"));
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/frontchannel-logout")).andExpect(status().isOk());
    }

    @Test
    void aSessionWithoutAnOidcLoginCannotRun() throws Exception {
        mockMvc().perform(post("/frontchannel-logout").with(user("hendi")).with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void anUnknownRunIdYieldsNothing() {
        assertThat(frontChannelLogoutService.find("not-a-run")).isNull();
        assertThat(frontChannelLogoutService.find(null)).isNull();
    }
}
