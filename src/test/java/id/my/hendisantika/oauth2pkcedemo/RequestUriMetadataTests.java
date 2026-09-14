package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import id.my.hendisantika.oauth2pkcedemo.service.RequestUriMetadataService;
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
 * Time: 16.05
 */
@SpringBootTest
class RequestUriMetadataTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private DemoProperties properties;

    @Autowired
    private JarRequestSigner signer;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /**
     * OpenID Connect Discovery section 3 gives these defaults, and two of them describe this server
     * backwards - which is the reason for publishing them rather than leaving them out.
     */
    @Test
    void bothDocumentsPublishTheThreeValues() throws Exception {
        for (String document : List.of("/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration")) {
            String metadata = mockMvc().perform(get(document))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();

            assertThat(metadata)
                    .contains("\"" + ServerMetadataCustomizer.REQUEST_PARAMETER_SUPPORTED + "\":true")
                    .contains("\"" + ServerMetadataCustomizer.REQUEST_URI_PARAMETER_SUPPORTED
                            + "\":true")
                    .contains("\"" + ServerMetadataCustomizer.REQUIRE_REQUEST_URI_REGISTRATION
                            + "\":true");
        }
    }

    /** RFC 9101 section 5.1, and what request_parameter_supported: true is claiming. */
    @Test
    void aRequestObjectByValueIsAccepted() throws Exception {
        DemoProperties.Client client = properties.fetchedRequestClient();
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", client.clientId());
        query.put(JwtSecuredAuthorizationRequestFilter.REQUEST,
                signer.sign(client.clientId(), properties.issuerUri(), parameters(client)));

        assertThat(authorize(query)).doesNotContain("error=");
    }

    /** A URL somewhere else is judged by the registration rules rather than by the lookup. */
    @Test
    void theSchemeIsWhatDecidesWhichCheckSpeaks() throws Exception {
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", properties.fetchedRequestClient().clientId());
        query.put("request_uri", "https://client.example.org/request-object.jwt");

        assertThat(refusal(query)).contains("not registered for this client");
    }

    /**
     * RFC 9126 section 5: a reference from the pushed endpoint is usable "regardless of other
     * authorization server metadata such as request_uri_parameter_supported".
     */
    @Test
    void aReferenceThatIsNotAUrlIsLeftToTheAuthorizationServer() throws Exception {
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", properties.confidentialClient().clientId());
        query.put("request_uri", RequestUriMetadataService.INVENTED_REFERENCE);

        // Past this filter, and refused by the endpoint that owns the reference - which is what a
        // real pushed reference passes through to be accepted.
        assertThat(refusal(query)).doesNotContain("does not fetch request objects by reference");
    }

    /** The page's own account of the defaults, kept beside the spec rather than in prose. */
    @Test
    void theDefaultsAreTheOnesTheSpecGives() {
        RequestUriMetadataService service = new RequestUriMetadataService(properties, signer);

        assertThat(service.defaultsIfOmitted())
                .containsEntry(ServerMetadataCustomizer.REQUEST_PARAMETER_SUPPORTED, false)
                .containsEntry(ServerMetadataCustomizer.REQUEST_URI_PARAMETER_SUPPORTED, true)
                .containsEntry(ServerMetadataCustomizer.REQUIRE_REQUEST_URI_REGISTRATION, false);
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/request-uri-metadata")).andExpect(status().isOk());
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
