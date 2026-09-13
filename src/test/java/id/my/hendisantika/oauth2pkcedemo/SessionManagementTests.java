package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.AuthorizationCodeBindingController;
import id.my.hendisantika.oauth2pkcedemo.controller.CheckSessionIframeController;
import id.my.hendisantika.oauth2pkcedemo.security.IssuerIdentifierResponseHandler;
import id.my.hendisantika.oauth2pkcedemo.security.OpBrowserState;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import id.my.hendisantika.oauth2pkcedemo.service.AuthorizationServerMetadataService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
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
 * Time: 20.25
 */
@SpringBootTest
class SessionManagementTests extends AbstractMySqlIntegrationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** Section 3.2, recomputed here the way the OP iframe's script recomputes it in the browser. */
    @Test
    void theSessionStateIsASaltedHashOfTheClientOriginAndBrowserState() throws Exception {
        String sessionState = OpBrowserState.sessionState(
                "pkce-demo-client", "http://localhost:8080", "a-browser-state", "0011223344556677");

        byte[] digest = MessageDigest.getInstance("SHA-256").digest(
                "pkce-demo-client http://localhost:8080 a-browser-state 0011223344556677"
                        .getBytes(StandardCharsets.UTF_8));
        assertThat(sessionState).isEqualTo(HexFormat.of().formatHex(digest) + ".0011223344556677");
        // The salt travels with the value, which is the only reason the browser can redo the sum.
        assertThat(sessionState.split("\\.")[1]).isEqualTo("0011223344556677");
        // Section 2: it must not contain a space, because the postMessage is space-separated.
        assertThat(sessionState).doesNotContain(" ");
    }

    /** Any change to the state at the provider changes the hash, which is the whole signal. */
    @Test
    void adifferentBrowserStateProducesADifferentSessionState() {
        String before = OpBrowserState.sessionState("c", "http://localhost:8080", "before", "abcd");
        String after = OpBrowserState.sessionState("c", "http://localhost:8080", "after", "abcd");

        assertThat(before).isNotEqualTo(after);
    }

    /** RFC 6454 section 4: scheme, host and port, and nothing else. */
    @Test
    void theOriginIsJustSchemeHostAndPort() {
        assertThat(OpBrowserState.originOf("http://localhost:8080/login/oauth2/code/pkce-demo-client"))
                .isEqualTo("http://localhost:8080");
        assertThat(OpBrowserState.originOf("https://example.com/cb?x=1"))
                .isEqualTo("https://example.com");
    }

    /** A client whose registration asks for no consent, so the response is the code rather than a page. */
    @Test
    void theAuthorizationResponseCarriesTheSessionState() throws Exception {
        MvcResult result = mockMvc().perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", properties.codeBindingClient().clientId())
                        .queryParam("redirect_uri",
                                properties.issuerUri() + AuthorizationCodeBindingController.CALLBACK_URI)
                        .queryParam("scope", "openid profile")
                        .queryParam("state", "a-state")
                        .queryParam("code_challenge", CODE_CHALLENGE)
                        .queryParam("code_challenge_method", "S256")
                        .with(user("hendi")))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl())
                .contains(IssuerIdentifierResponseHandler.SESSION_STATE + "=");
        Cookie browserState = result.getResponse().getCookie(OpBrowserState.COOKIE_NAME);
        assertThat(browserState).isNotNull();
        // The provider's iframe reads this from script, so it cannot be HttpOnly.
        assertThat(browserState.isHttpOnly()).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void bothMetadataDocumentsNameTheIframe() throws Exception {
        for (String suffix : List.of(AuthorizationServerMetadataService.OAUTH_SUFFIX,
                AuthorizationServerMetadataService.OIDC_SUFFIX)) {
            String body = mockMvc().perform(get("/.well-known/" + suffix))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();
            assertThat(MAPPER.readValue(body, Map.class))
                    .as("%s", suffix)
                    .containsEntry(ServerMetadataCustomizer.CHECK_SESSION_IFRAME,
                            properties.issuerUri() + CheckSessionIframeController.URI);
        }
    }

    /**
     * The iframe is a page and has to be reachable by a browser that may have no session here - not
     * having one is one of the answers it exists to give.
     */
    @Test
    void theIframeIsServedToAnyone() throws Exception {
        String body = mockMvc().perform(get(CheckSessionIframeController.URI))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(body)
                .contains(OpBrowserState.COOKIE_NAME)
                .contains("'unchanged'")
                .contains("'changed'")
                .contains("'error'")
                // Section 6: it must refuse messages from anywhere it does not expect.
                .contains("event.origin !== window.location.origin");
    }

    @Test
    void changingTheStateAtTheProviderIssuesADifferentOne() throws Exception {
        MockHttpServletResponse response = mockMvc()
                .perform(post("/session-management/change").with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andReturn().getResponse();

        Cookie changed = response.getCookie(OpBrowserState.COOKIE_NAME);
        assertThat(changed).isNotNull();
        assertThat(changed.getValue()).isNotBlank();
        assertThat(changed.isHttpOnly()).isFalse();
        assertThat(changed.getPath()).isEqualTo("/");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/session-management")).andExpect(status().isOk());
    }
}
