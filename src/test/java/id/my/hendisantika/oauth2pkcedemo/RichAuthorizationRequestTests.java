package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.RichAuthorizationDetail;
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
import java.util.List;

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
 * Time: 15.52
 */
@SpringBootTest
class RichAuthorizationRequestTests extends AbstractMySqlIntegrationTest {

    private static final String PAYMENT = """
            [{"type":"payment_initiation","actions":["initiate"],
              "locations":["https://api.example.com/payments"],
              "instructedAmount":{"currency":"EUR","amount":"123.50"},
              "creditorName":"Merchant A"}]""";

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
    void detailsAreParsedIntoTypeActionsAndWhateverElseTheTypeDefines() {
        List<RichAuthorizationDetail> details = RichAuthorizationDetail.parse(PAYMENT);

        assertThat(details).hasSize(1);
        RichAuthorizationDetail detail = details.get(0);
        assertThat(detail.type()).isEqualTo("payment_initiation");
        assertThat(detail.actions()).containsExactly("initiate");
        assertThat(detail.locations()).containsExactly("https://api.example.com/payments");
        // Type-specific fields are kept as they came, so the consent screen can render them.
        assertThat(detail.other()).containsKeys("instructedAmount", "creditorName");
        assertThat(detail.summary()).isEqualTo("Initiate a payment of 123.50 EUR to Merchant A");
    }

    @Test
    void malformedDetailsAreRejectedRatherThanIgnored() {
        assertThatThrownBy(() -> RichAuthorizationDetail.parse("not json"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RichAuthorizationDetail.parse("{\"type\":\"payment_initiation\"}"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void onlyImplementedTypesAreAccepted() {
        assertThat(RichAuthorizationDetail.unsupportedTypes(PAYMENT)).isEmpty();
        assertThat(RichAuthorizationDetail.unsupportedTypes("[{\"type\":\"open_the_vault\"}]"))
                .containsExactly("open_the_vault");
    }

    @Test
    void pushingAnUnsupportedTypeIsRefusedBeforeAnyoneIsAskedToApproveIt() throws Exception {
        MvcResult result = mockMvc().perform(pushWith("[{\"type\":\"open_the_vault\"}]"))
                .andExpect(status().isBadRequest())
                .andReturn();

        // RFC 9396 section 5 names this error for exactly this case.
        assertThat(result.getResponse().getContentAsString())
                .contains("invalid_authorization_details")
                .contains("open_the_vault");
    }

    @Test
    void pushingASupportedTypeIsAccepted() throws Exception {
        mockMvc().perform(pushWith(PAYMENT)).andExpect(status().isCreated());
    }

    @Test
    void theRarPageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/rar")).andExpect(status().isOk());
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder pushWith(
            String authorizationDetails) {
        DemoProperties.Client client = properties.confidentialClient();
        return post(settings.getPushedAuthorizationRequestEndpoint())
                .header("Authorization", confidentialClientCredentials())
                .param("response_type", "code")
                .param("client_id", client.clientId())
                .param("scope", "openid")
                .param("state", "rar-test")
                .param("redirect_uri",
                        properties.issuerUri() + "/login/oauth2/code/" + client.registrationId())
                .param("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .param("code_challenge_method", "S256")
                .param("authorization_details", authorizationDetails);
    }
}
