package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.service.TokenExchangeService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
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
 * Time: 15.04
 */
@SpringBootTest
class TokenExchangeTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private AuthorizationServerSettings settings;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    private String exchangeClientCredentials() {
        DemoProperties.Client client = properties.exchangeClient();
        return "Basic " + Base64.getEncoder().encodeToString(
                (client.clientId() + ":" + client.clientSecret()).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void theExchangeClientCarriesBothGrantsItNeeds() {
        RegisteredClient client =
                registeredClientRepository.findByClientId(properties.exchangeClient().clientId());

        assertThat(client).isNotNull();
        assertThat(client.getAuthorizationGrantTypes())
                // Token exchange to trade the user's token, client credentials to mint the actor
                // token that turns impersonation into delegation.
                .containsExactlyInAnyOrder(AuthorizationGrantType.TOKEN_EXCHANGE,
                        AuthorizationGrantType.CLIENT_CREDENTIALS);
        assertThat(client.getScopes()).containsExactlyInAnyOrder("api.read", "api.write");
    }

    @Test
    void noOtherClientMayExchangeTokens() {
        // The grant is deliberately not handed to the browser-facing clients: exchanging is what a
        // downstream service does with a token it received, not something a front end needs.
        for (String clientId : java.util.List.of(properties.client().clientId(),
                properties.confidentialClient().clientId())) {
            RegisteredClient client = registeredClientRepository.findByClientId(clientId);
            assertThat(client.getAuthorizationGrantTypes())
                    .as("grants of %s", clientId)
                    .doesNotContain(AuthorizationGrantType.TOKEN_EXCHANGE);
        }
    }

    @Test
    void exchangingAnUnknownSubjectTokenIsRefused() throws Exception {
        MvcResult result = mockMvc().perform(post(settings.getTokenEndpoint())
                        .header("Authorization", exchangeClientCredentials())
                        .param("grant_type", TokenExchangeService.TOKEN_EXCHANGE_GRANT)
                        .param("subject_token", "a-token-that-was-never-issued")
                        .param("subject_token_type", TokenExchangeService.ACCESS_TOKEN_TYPE)
                        .param("scope", "api.read"))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).contains("invalid_grant");
    }

    @Test
    void exchangingWithoutClientAuthenticationIsRefused() throws Exception {
        // Only a registered client may exchange; otherwise a stolen token could be traded by anyone.
        mockMvc().perform(post(settings.getTokenEndpoint())
                        .param("grant_type", TokenExchangeService.TOKEN_EXCHANGE_GRANT)
                        .param("subject_token", "anything")
                        .param("subject_token_type", TokenExchangeService.ACCESS_TOKEN_TYPE))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void theExchangePageRequiresAnAuthenticatedSession() throws Exception {
        MvcResult result = mockMvc().perform(get("/exchange"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl())
                .endsWith("/oauth2/authorization/" + properties.client().registrationId());
    }
}
