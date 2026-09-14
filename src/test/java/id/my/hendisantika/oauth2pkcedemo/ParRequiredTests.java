package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.PushedAuthorizationRequiredFilter;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectClientRegistrationConverters;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import id.my.hendisantika.oauth2pkcedemo.service.ParRequiredService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
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
 * Date: 16/09/26
 * Time: 22.40
 */
@SpringBootTest
class ParRequiredTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private DemoProperties properties;

    @Autowired
    private JarRequestSigner signer;

    @Autowired
    private RegisteredClientRepository registeredClients;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** RFC 9126 section 6, as a setting Spring Authorization Server has no field for. */
    @Test
    void theClientRegistersTheLock() {
        RegisteredClient client = registeredClients
                .findByClientId(properties.parRequiredClient().clientId());

        assertThat(client).isNotNull();
        assertThat(client.getClientSettings()
                .<Object>getSetting(PushedAuthorizationRequiredFilter.REQUIRE_PAR_SETTING))
                .isEqualTo(true);
    }

    /** The same request, from a client that did not register it, is acted on. */
    @Test
    void anOrdinaryRequestFromAnUnlockedClientIsAccepted() throws Exception {
        assertThat(authorize(parameters(properties.confidentialClient())))
                .doesNotContain("error=");
    }

    /** And from the one that did, it is not - which is the whole of the setting. */
    @Test
    void anOrdinaryRequestFromTheLockedClientIsRefused() throws Exception {
        assertThat(refusal(parameters(properties.parRequiredClient())))
                .contains("invalid_request")
                .contains("This client registered require_pushed_authorization_requests");
    }

    /**
     * The filter asks only whether the request was started by pushing. Whether the reference is real
     * is the authorization server's own check, and the two refusals read differently.
     */
    @Test
    void aRequestUriIsEnoughForThisFilterAndNotForTheServer() throws Exception {
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", properties.parRequiredClient().clientId());
        query.put("request_uri", ParRequiredService.INVENTED_REQUEST_URI);

        // The status is the assertion: the authorization server renders its own error through a
        // handler that writes nothing to the mock response, so only the filter's refusals carry a
        // body here. That is exactly what makes the body a good test of which check spoke.
        assertThat(refusal(query))
                .as("past the filter, and refused by the endpoint behind it")
                .doesNotContain("require_pushed_authorization_requests")
                .isEmpty();
    }

    /** JAR is a different lock: signing the request does not make it a pushed one. */
    @Test
    void aSignedRequestObjectDoesNotSatisfyTheLock() throws Exception {
        DemoProperties.Client client = properties.parRequiredClient();
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", client.clientId());
        query.put("request", signer.sign(client.clientId(), properties.issuerUri(),
                parameters(client)));

        assertThat(refusal(query))
                .contains("This client registered require_pushed_authorization_requests");
    }

    /** RFC 9126 section 6 is client metadata, so a registration request may carry it. */
    @Test
    void aRegistrationRequestCarriesTheLockOntoTheClient() {
        RegisteredClient client = RequestObjectClientRegistrationConverters.registeredClient()
                .convert(OidcClientRegistration.withClaims(Map.of(
                        "client_name", "Ad hoc client",
                        "redirect_uris", List.of(properties.issuerUri() + "/login/oauth2/code/adhoc"),
                        "grant_types", List.of("authorization_code"),
                        "response_types", List.of("code"),
                        RequestObjectClientRegistrationConverters.REQUIRE_PAR, true)).build());

        assertThat(client).isNotNull();
        assertThat(client.getClientSettings()
                .<Object>getSetting(PushedAuthorizationRequiredFilter.REQUIRE_PAR_SETTING))
                .isEqualTo(true);
    }

    /**
     * RFC 9126 section 5's server-wide value is published, and false: the lock this server
     * implements is the per-client one from section 6.
     */
    @Test
    void theServerWideValueIsPublishedAndFalse() throws Exception {
        for (String document : List.of("/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration")) {
            assertThat(mockMvc().perform(get(document))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString())
                    .contains("\"" + ServerMetadataCustomizer.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS
                            + "\":false");
        }
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/par-required")).andExpect(status().isOk());
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
