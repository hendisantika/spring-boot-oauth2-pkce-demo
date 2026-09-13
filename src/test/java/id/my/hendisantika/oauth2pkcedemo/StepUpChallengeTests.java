package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.config.StrongResourceSecurityConfig;
import id.my.hendisantika.oauth2pkcedemo.controller.StrongResourceController;
import id.my.hendisantika.oauth2pkcedemo.security.AuthenticationContextLevel;
import id.my.hendisantika.oauth2pkcedemo.security.InsufficientUserAuthenticationHandler;
import id.my.hendisantika.oauth2pkcedemo.security.StepUpChallenge;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
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
 * Date: 14/09/26
 * Time: 14.10
 */
@SpringBootTest
class StepUpChallengeTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /**
     * RFC 9470 section 3. A valid token that was not earned strongly enough is answered with 401 and
     * a challenge naming the level, not with a refusal the client can do nothing about.
     */
    @Test
    void aTokenWithTooLowAnAcrIsAnsweredWithAChallenge() throws Exception {
        MvcResult result = mockMvc().perform(post(StrongResourceController.TRANSFER_URI)
                        .with(jwt().jwt(builder -> builder.claim("acr", AuthenticationContextLevel.LOA_1))))
                .andExpect(status().isUnauthorized())
                .andReturn();

        StepUpChallenge challenge = StepUpChallenge.parse(
                result.getResponse().getHeader(HttpHeaders.WWW_AUTHENTICATE));

        assertThat(challenge).isNotNull();
        assertThat(challenge.scheme()).isEqualTo("Bearer");
        assertThat(challenge.asksForStrongerAuthentication()).isTrue();
        assertThat(challenge.acrValues()).isEqualTo(StrongResourceSecurityConfig.REQUIRED_ACR);
        assertThat(challenge.maxAge())
                .isEqualTo(String.valueOf(StrongResourceSecurityConfig.MAX_AGE_SECONDS));
    }

    /** The same call, once the user has authenticated the way the challenge asked. */
    @Test
    void theSameCallSucceedsOnceTheAcrIsHighEnough() throws Exception {
        MvcResult result = mockMvc().perform(post(StrongResourceController.TRANSFER_URI)
                        .with(jwt().jwt(builder -> builder
                                .subject("hendi")
                                .claim("acr", AuthenticationContextLevel.LOA_2))))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getContentAsString())
                .contains("\"transferred\"")
                .contains(AuthenticationContextLevel.LOA_2);
        // Nothing about the operation changed - only how the caller authenticated.
        assertThat(result.getResponse().getHeader(HttpHeaders.WWW_AUTHENTICATE)).isNull();
    }

    /**
     * What Spring Security answers instead, and why it is the wrong answer here: a scope is granted
     * once and the user cannot fix it by trying harder, so 403 is final. An authentication level can
     * be raised, which is what the 401 invites.
     */
    @Test
    void springSecurityWouldHaveSaidInsufficientScopeAndForbidden() throws Exception {
        MockHttpServletResponse shipped = new MockHttpServletResponse();
        new BearerTokenAccessDeniedHandler().handle(new MockHttpServletRequest(), shipped,
                new AccessDeniedException("denied"));

        assertThat(shipped.getStatus()).isEqualTo(403);
        assertThat(shipped.getHeader(HttpHeaders.WWW_AUTHENTICATE)).doesNotContain("acr_values");

        MockHttpServletResponse ours = new MockHttpServletResponse();
        new InsufficientUserAuthenticationHandler(AuthenticationContextLevel.LOA_2, 300)
                .handle(new MockHttpServletRequest(), ours, new AccessDeniedException("denied"));

        assertThat(ours.getStatus()).isEqualTo(401);
        assertThat(ours.getHeader(HttpHeaders.WWW_AUTHENTICATE))
                .contains(StepUpChallenge.INSUFFICIENT_USER_AUTHENTICATION)
                .contains("acr_values=\"" + AuthenticationContextLevel.LOA_2 + "\"")
                .contains("max_age=\"300\"");
    }

    /** A client reads the header; a challenge about a scope is not one it can step up for. */
    @Test
    void onlyAStepUpChallengeTellsTheClientToSendTheUserBack() {
        StepUpChallenge scope = StepUpChallenge.parse(
                "Bearer error=\"insufficient_scope\", error_description=\"nope\", scope=\"api.write\"");

        assertThat(scope).isNotNull();
        assertThat(scope.asksForStrongerAuthentication()).isFalse();
        assertThat(scope.acrValues()).isNull();
        assertThat(StepUpChallenge.parse(null)).isNull();
    }

    @Test
    void thePageSendsAnAnonymousVisitorThroughTheLogin() throws Exception {
        MvcResult result = mockMvc().perform(get("/stepup-challenge"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl())
                .endsWith("/oauth2/authorization/" + properties.client().registrationId());
    }
}
