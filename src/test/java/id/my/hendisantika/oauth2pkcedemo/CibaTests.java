package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.entity.CibaRequest;
import id.my.hendisantika.oauth2pkcedemo.security.CibaAuthenticationToken;
import id.my.hendisantika.oauth2pkcedemo.service.CibaService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
 * Time: 16.10
 */
@SpringBootTest
class CibaTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private CibaService cibaService;

    @Autowired
    private AuthorizationServerSettings settings;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    private String cibaClientCredentials() {
        DemoProperties.Client client = properties.cibaClient();
        return "Basic " + Base64.getEncoder().encodeToString(
                (client.clientId() + ":" + client.clientSecret()).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void theClientIsRegisteredForTheCibaGrantAndNothingElse() {
        RegisteredClient client = registeredClientRepository.findByClientId(properties.cibaClient().clientId());

        assertThat(client).isNotNull();
        assertThat(client.getAuthorizationGrantTypes())
                .containsExactly(CibaAuthenticationToken.CIBA_GRANT_TYPE);
        // No redirect URI: the user is never sent anywhere, which is the whole point.
        assertThat(client.getRedirectUris()).isEmpty();
    }

    @Test
    void theBackchannelEndpointRefusesAnUnauthenticatedClient() throws Exception {
        mockMvc().perform(post("/backchannel/authenticate")
                        .param("scope", "api.read")
                        .param("login_hint", "hendi"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void aHintThatNamesNobodyIsRefused() throws Exception {
        MvcResult result = mockMvc().perform(post("/backchannel/authenticate")
                        .header("Authorization", cibaClientCredentials())
                        .param("scope", "api.read")
                        .param("login_hint", "not-a-user"))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).contains("unknown_user_id");
    }

    @Test
    void openingARequestReturnsAnIdAnExpiryAndAPollingInterval() throws Exception {
        MvcResult result = mockMvc().perform(post("/backchannel/authenticate")
                        .header("Authorization", cibaClientCredentials())
                        .param("scope", "api.read")
                        .param("login_hint", "hendi")
                        .param("binding_message", "Transfer 250.00 EUR"))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getContentAsString())
                .contains("auth_req_id").contains("expires_in").contains("interval");
    }

    @Test
    void pollingBeforeTheUserAnswersIsPendingRatherThanAFailure() throws Exception {
        CibaRequest request = cibaService.start(properties.cibaClient().clientId(), "hendi",
                "api.read", "Poll me");

        MvcResult result = mockMvc().perform(post(settings.getTokenEndpoint())
                        .header("Authorization", cibaClientCredentials())
                        .param("grant_type", CibaAuthenticationToken.CIBA_GRANT_TYPE.getValue())
                        .param("auth_req_id", request.getAuthReqId()))
                .andReturn();

        // A normal step in the flow, with its own error code the client is expected to act on.
        assertThat(result.getResponse().getContentAsString()).contains("authorization_pending");
    }

    @Test
    void aRefusalIsReportedAsAccessDenied() throws Exception {
        CibaRequest request = cibaService.start(properties.cibaClient().clientId(), "hendi",
                "api.read", "Deny me");
        cibaService.decide(request.getAuthReqId(), "hendi", false);

        MvcResult result = mockMvc().perform(post(settings.getTokenEndpoint())
                        .header("Authorization", cibaClientCredentials())
                        .param("grant_type", CibaAuthenticationToken.CIBA_GRANT_TYPE.getValue())
                        .param("auth_req_id", request.getAuthReqId()))
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).contains("access_denied");
    }

    @Test
    void onlyTheUserNamedByTheRequestCanAnswerIt() {
        CibaRequest request = cibaService.start(properties.cibaClient().clientId(), "hendi",
                "api.read", "Not yours");

        cibaService.decide(request.getAuthReqId(), "itadmin", true);

        assertThat(cibaService.find(request.getAuthReqId()))
                .hasValueSatisfying(unchanged ->
                        assertThat(unchanged.getStatus()).isEqualTo(CibaRequest.Status.PENDING));
    }

    @Test
    void anUnknownHintIsRejectedByTheServiceItself() {
        assertThatThrownBy(() -> cibaService.start(properties.cibaClient().clientId(), "nobody",
                "api.read", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theCibaPageIsReachableWithoutSigningIn() throws Exception {
        // The client's backend drives this; the user never visits it.
        mockMvc().perform(get("/ciba")).andExpect(status().isOk());
    }
}
