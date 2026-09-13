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
 * Time: 13.56
 */
@SpringBootTest
class IntrospectionAndRevocationTests extends AbstractMySqlIntegrationTest {

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
    void introspectionRequiresAnAuthenticatedClient() throws Exception {
        // RFC 7662 section 2.1: the endpoint must not be open, or it becomes a token oracle.
        mockMvc().perform(post(settings.getTokenIntrospectionEndpoint()).param("token", "anything"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void revocationRequiresAnAuthenticatedClient() throws Exception {
        mockMvc().perform(post(settings.getTokenRevocationEndpoint()).param("token", "anything"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void introspectingAnUnknownTokenSaysOnlyThatItIsNotActive() throws Exception {
        MvcResult result = mockMvc().perform(post(settings.getTokenIntrospectionEndpoint())
                        .header("Authorization", confidentialClientCredentials())
                        .param("token", "a-token-that-was-never-issued"))
                .andExpect(status().isOk())
                .andReturn();

        // Section 2.2: revoked, expired and never-existed are indistinguishable.
        assertThat(result.getResponse().getContentAsString()).isEqualTo("{\"active\":false}");
    }

    @Test
    void revokingAnUnknownTokenIsStillAccepted() throws Exception {
        // RFC 7009 section 2.2: answering 200 regardless stops the endpoint being used to probe
        // which tokens exist.
        mockMvc().perform(post(settings.getTokenRevocationEndpoint())
                        .header("Authorization", confidentialClientCredentials())
                        .param("token", "a-token-that-was-never-issued")
                        .param("token_type_hint", "access_token"))
                .andExpect(status().isOk());
    }

    @Test
    void theIntrospectPageRequiresAnAuthenticatedSession() throws Exception {
        MvcResult result = mockMvc().perform(get("/introspect"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl())
                .endsWith("/oauth2/authorization/" + properties.client().registrationId());
    }
}
