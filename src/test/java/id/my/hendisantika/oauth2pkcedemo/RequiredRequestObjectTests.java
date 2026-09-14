package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectPolicy;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.LinkedHashMap;
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
 * Date: 16/09/26
 * Time: 17.20
 */
@SpringBootTest
class RequiredRequestObjectTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private JarRequestSigner signer;

    @Autowired
    private DemoProperties properties;

    @Autowired
    private RequestObjectPolicy policy;

    /** Nothing here may leave the switch on for whatever runs next. */
    @AfterEach
    void restoreTheSwitch() {
        policy.requireSignedRequestObject(
                ServerMetadataCustomizer.REQUIRE_SIGNED_REQUEST_OBJECT_DEFAULT);
    }

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** The server starts with the switch off, which is the only reason every other page works. */
    @Test
    void theSwitchStartsOff() {
        assertThat(ServerMetadataCustomizer.REQUIRE_SIGNED_REQUEST_OBJECT_DEFAULT).isFalse();
        assertThat(policy.requireSignedRequestObject()).isFalse();
    }

    /**
     * RFC 9101 section 10.5's first sentence. An ordinary RFC 6749 request bypasses everything JAR
     * provides, so where JAR is required its absence is the thing to refuse.
     */
    @Test
    void anOrdinaryRequestIsAcceptedUntilTheSwitchIsOn() throws Exception {
        DemoProperties.Client client = properties.client();

        assertThat(authorize(plain(client))).doesNotContain("error=");

        policy.requireSignedRequestObject(true);
        assertThat(refusal(plain(client)))
                .contains("invalid_request")
                .contains("This server requires request objects to be signed");
    }

    /** The switch removes ways of asking rather than adding checks to the one that remains. */
    @Test
    void aSignedRequestObjectIsAcceptedUnderBothSettings() throws Exception {
        DemoProperties.Client client = properties.client();
        Map<String, String> signed = withRequestObject(client,
                signer.sign(client.clientId(), properties.issuerUri(), parameters(client)));

        assertThat(authorize(signed)).doesNotContain("error=");

        policy.requireSignedRequestObject(true);
        assertThat(authorize(signed)).doesNotContain("error=");
    }

    /** The second sentence of the same section: not signed is not enough either. */
    @Test
    void anUnsignedRequestObjectIsRefusedWhileTheSwitchIsOn() throws Exception {
        DemoProperties.Client client = properties.jarNoneClient();
        Map<String, String> unsigned = withRequestObject(client,
                signer.unsigned(client.clientId(), properties.issuerUri(), parameters(client)));

        assertThat(authorize(unsigned)).doesNotContain("error=");

        policy.requireSignedRequestObject(true);
        assertThat(refusal(unsigned)).contains("This server requires request objects to be signed");
    }

    /** Client metadata locks one door without the server locking all of them. */
    @Test
    void theClientSideSwitchRefusesAnOrdinaryRequestOnItsOwn() throws Exception {
        assertThat(policy.requireSignedRequestObject()).isFalse();

        assertThat(refusal(plain(properties.jarNoneStrictClient())))
                .contains("This client registered require_signed_request_object");
    }

    /** What is published follows the switch, rather than describing a value fixed at startup. */
    @Test
    void theMetadataFollowsTheSwitch() throws Exception {
        for (String document : java.util.List.of("/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration")) {
            assertThat(metadata(document)).contains("\"require_signed_request_object\":false");
        }

        policy.requireSignedRequestObject(true);
        for (String document : java.util.List.of("/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration")) {
            assertThat(metadata(document)).contains("\"require_signed_request_object\":true");
        }
    }

    /**
     * The consent screen posts back to the same endpoint to continue a request that was already
     * checked; judging that as a fresh one would refuse the user's own approval.
     */
    @Test
    void onlyTheAuthorizationRequestItselfIsJudged() throws Exception {
        policy.requireSignedRequestObject(true);

        mockMvc().perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/oauth2/authorize")
                        .param("client_id", properties.client().clientId())
                        .param("state", "a-state")
                        .with(user("hendi"))
                        .with(org.springframework.security.test.web.servlet.request
                                .SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(result -> assertThat(result.getResponse().getContentAsString())
                        .doesNotContain("requires request objects to be signed"));
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jar-required")).andExpect(status().isOk());
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

    private Map<String, String> plain(DemoProperties.Client client) {
        return parameters(client);
    }

    private Map<String, String> withRequestObject(DemoProperties.Client client, String requestObject) {
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", client.clientId());
        query.put("request", requestObject);
        return query;
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
