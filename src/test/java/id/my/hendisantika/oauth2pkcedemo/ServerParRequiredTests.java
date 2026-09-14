package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.FapiCheck;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.PushedAuthorizationPolicy;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import id.my.hendisantika.oauth2pkcedemo.service.FapiComplianceService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 17/09/26
 * Time: 08.15
 */
@SpringBootTest
class ServerParRequiredTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private DemoProperties properties;

    @Autowired
    private JarRequestSigner signer;

    @Autowired
    private PushedAuthorizationPolicy policy;

    @Autowired
    private FapiComplianceService fapiComplianceService;

    /** Nothing here may leave the switch on for whatever runs next. */
    @AfterEach
    void restoreTheSwitch() {
        policy.requirePushedRequests(PushedAuthorizationPolicy.REQUIRE_PUSHED_REQUESTS_DEFAULT);
    }

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** The server starts with the switch off, which is why every other page works. */
    @Test
    void theSwitchStartsOff() {
        assertThat(PushedAuthorizationPolicy.REQUIRE_PUSHED_REQUESTS_DEFAULT).isFalse();
        assertThat(policy.requirePushedRequests()).isFalse();
    }

    /** RFC 9126 section 5: authorization request data only via PAR, for every client. */
    @Test
    void anOrdinaryRequestIsAcceptedUntilTheSwitchIsOn() throws Exception {
        DemoProperties.Client client = properties.confidentialClient();

        assertThat(authorize(parameters(client))).doesNotContain("error=");

        policy.requirePushedRequests(true);
        assertThat(refusal(parameters(client)))
                .contains("invalid_request")
                .contains("This server accepts authorization request data only via PAR");
    }

    /** The switch removes ways of asking rather than adding checks to the one that remains. */
    @Test
    void aSignedRequestObjectIsNotAPushedOne() throws Exception {
        DemoProperties.Client client = properties.confidentialClient();
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", client.clientId());
        query.put("request", signer.sign(client.clientId(), properties.issuerUri(),
                parameters(client)));

        assertThat(authorize(query)).doesNotContain("error=");

        policy.requirePushedRequests(true);
        assertThat(refusal(query)).contains("only via PAR");
    }

    /** A client cannot register its way out of the server's rule. */
    @Test
    void theServerWideRuleOutranksTheClientRegistration() throws Exception {
        DemoProperties.Client locked = properties.parRequiredClient();

        assertThat(refusal(parameters(locked)))
                .contains("This client registered require_pushed_authorization_requests");

        policy.requirePushedRequests(true);
        assertThat(refusal(parameters(locked)))
                .contains("This server accepts authorization request data only via PAR");
    }

    /** What is published follows the switch, which is what makes it server metadata. */
    @Test
    void theMetadataFollowsTheSwitch() throws Exception {
        String name = ServerMetadataCustomizer.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS;
        for (String document : documents()) {
            assertThat(metadata(document)).contains("\"" + name + "\":false");
        }

        policy.requirePushedRequests(true);
        for (String document : documents()) {
            assertThat(metadata(document)).contains("\"" + name + "\":true");
        }
    }

    /**
     * And so does the profile page: that check reads the running configuration, so the requirement
     * it has been failing passes while the switch is on.
     */
    @Test
    void theFapiRowFollowsTheSwitch() {
        assertThat(parRow().outcome()).isEqualTo(FapiCheck.Outcome.FAIL);

        policy.requirePushedRequests(true);
        assertThat(parRow().outcome()).isEqualTo(FapiCheck.Outcome.PASS);
        assertThat(parRow().observed()).contains("server-wide require_pushed_authorization_requests "
                + "is true");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/par-server-required")).andExpect(status().isOk());
    }

    private FapiCheck parRow() {
        return fapiComplianceService.serverChecks().stream()
                .filter(check -> check.requirement().contains("requires pushed authorization requests"))
                .findFirst()
                .orElseThrow();
    }

    private static List<String> documents() {
        return List.of("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration");
    }

    private String metadata(String document) throws Exception {
        return mockMvc().perform(get(document))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    private MvcResult perform(Map<String, String> query) throws Exception {
        var request = get("/oauth2/authorize").with(user("hendi"));
        query.forEach(request::queryParam);
        return mockMvc().perform(request).andReturn();
    }

    private String authorize(Map<String, String> query) throws Exception {
        MvcResult result = perform(query);
        assertThat(result.getResponse().getStatus()).isEqualTo(302);
        return result.getResponse().getRedirectedUrl();
    }

    private String refusal(Map<String, String> query) throws Exception {
        MvcResult result = perform(query);
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        return result.getResponse().getContentAsString();
    }

    private Map<String, String> parameters(DemoProperties.Client client) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("response_type", "code");
        parameters.put("client_id", client.clientId());
        parameters.put("scope", String.join(" ", client.scopes()));
        parameters.put("redirect_uri", properties.issuerUri() + "/login/oauth2/code/"
                + client.registrationId());
        parameters.put("state", "a-state");
        parameters.put("code_challenge", CODE_CHALLENGE);
        parameters.put("code_challenge_method", "S256");
        return parameters;
    }
}
