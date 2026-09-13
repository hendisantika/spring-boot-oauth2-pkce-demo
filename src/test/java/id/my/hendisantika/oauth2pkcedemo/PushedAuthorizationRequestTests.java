package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
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
 * Time: 14.16
 */
@SpringBootTest
class PushedAuthorizationRequestTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private AuthorizationServerSettings settings;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    private String confidentialClientCredentials() {
        DemoProperties.Client client = properties.confidentialClient();
        return "Basic " + Base64.getEncoder().encodeToString(
                (client.clientId() + ":" + client.clientSecret()).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void theEndpointIsAdvertisedOnlyBecauseItWasSwitchedOn() throws Exception {
        // Spring Authorization Server leaves PAR off unless the configurer enables it, and the
        // metadata document follows suit.
        MvcResult result = mockMvc().perform(get("/.well-known/oauth-authorization-server"))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getContentAsString())
                .contains("\"pushed_authorization_request_endpoint\"")
                .contains(properties.issuerUri() + settings.getPushedAuthorizationRequestEndpoint());
    }

    @Test
    void pushingRequiresAnAuthenticatedClient() throws Exception {
        // An unauthenticated push would let anyone mint request handles for a client.
        mockMvc().perform(post(settings.getPushedAuthorizationRequestEndpoint())
                        .param("response_type", "code")
                        .param("client_id", properties.confidentialClient().clientId())
                        .param("code_challenge", CODE_CHALLENGE)
                        .param("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void pushingReturnsASingleUseRequestUri() throws Exception {
        MvcResult result = mockMvc().perform(post(settings.getPushedAuthorizationRequestEndpoint())
                        .header("Authorization", confidentialClientCredentials())
                        .param("response_type", "code")
                        .param("client_id", properties.confidentialClient().clientId())
                        .param("scope", "openid profile")
                        .param("state", "par-state")
                        .param("redirect_uri", properties.issuerUri() + "/login/oauth2/code/"
                                + properties.confidentialClient().registrationId())
                        .param("code_challenge", CODE_CHALLENGE)
                        .param("code_challenge_method", "S256"))
                .andExpect(status().isCreated())
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertThat(body).contains("urn:ietf:params:oauth:request_uri:").contains("expires_in");
        // The request itself is not echoed back - only a handle to it.
        assertThat(body).doesNotContain(CODE_CHALLENGE).doesNotContain("par-state");
    }

    @Test
    void anUnknownRequestUriIsRefusedAtTheAuthorizationEndpoint() throws Exception {
        MvcResult result = mockMvc().perform(get(settings.getAuthorizationEndpoint())
                        .param("client_id", properties.confidentialClient().clientId())
                        .param("request_uri", "urn:ietf:params:oauth:request_uri:made-up"))
                .andReturn();

        assertThat(result.getResponse().getStatus()).isNotEqualTo(200);
    }

    @Test
    void theParPageIsReachableWithoutSigningIn() throws Exception {
        // Pushing the request is the first step of logging in, not something done from a session.
        mockMvc().perform(get("/par")).andExpect(status().isOk());
    }
}
