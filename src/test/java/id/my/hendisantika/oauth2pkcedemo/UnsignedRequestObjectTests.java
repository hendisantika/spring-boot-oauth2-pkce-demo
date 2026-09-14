package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jose.jwk.RSAKey;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
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
 * Time: 14.30
 */
@SpringBootTest
class UnsignedRequestObjectTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private JarRequestSigner signer;

    @Autowired
    private RSAKey requestDecryptionKey;

    @Autowired
    private DemoProperties properties;

    @Autowired
    private RegisteredClientRepository registeredClients;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** OpenID Connect Dynamic Client Registration: "the value none MAY be used". */
    @Test
    void aClientMayRegisterNone() {
        assertThat(setting(properties.jarNoneClient(),
                JwtSecuredAuthorizationRequestFilter.SIGNING_ALG_SETTING)).isEqualTo("none");
        assertThat(JwtSecuredAuthorizationRequestFilter.SUPPORTED_SIGNING_ALGS).contains("none");
    }

    /** And then an unsigned request object is acted on like any other. */
    @Test
    void anUnsignedRequestObjectFromThatClientIsAccepted() throws Exception {
        DemoProperties.Client client = properties.jarNoneClient();
        String unsigned = unsigned(client, Map.of());

        assertThat(JWTParser.parse(unsigned)).isInstanceOf(PlainJWT.class);
        assertThat(authorize(client, unsigned)).doesNotContain("error=");
    }

    /**
     * {@code none} is a value in the agreement rather than an escape from it: a properly signed
     * object from a client that registered {@code none} is still not what it registered.
     */
    @Test
    void aSignedObjectFromAClientThatRegisteredNoneIsRefused() throws Exception {
        DemoProperties.Client client = properties.jarNoneClient();
        String signed = signer.sign(client.clientId(), properties.issuerUri(), parameters(client));

        assertThat(refusal(client, signed))
                .contains("signed with RS256")
                .contains("registered none");
    }

    /** RFC 9101 section 10.5, as client metadata, against the same client's own registration. */
    @Test
    void theClientSideDowngradeDefenceOutranksTheRegisteredAlgorithm() throws Exception {
        DemoProperties.Client client = properties.jarNoneStrictClient();

        assertThat(setting(client, JwtSecuredAuthorizationRequestFilter.SIGNING_ALG_SETTING))
                .isEqualTo("none");
        assertThat(setting(client, JwtSecuredAuthorizationRequestFilter.REQUIRE_SIGNED_SETTING))
                .isEqualTo("true");
        assertThat(refusal(client, unsigned(client, Map.of())))
                .contains("registered require_signed_request_object");
    }

    /**
     * Encryption answers a different question from signing. Anyone can address a JWE to a key this
     * server publishes, so an accepted encrypted-but-unsigned object says nothing about who sent it.
     */
    @Test
    void anUnsignedObjectInsideAJweIsStillUnsigned() throws Exception {
        DemoProperties.Client client = properties.jarNoneClient();
        String encrypted = signer.encrypt(unsigned(client, Map.of()),
                requestDecryptionKey.toPublicJWK());

        assertThat(encrypted.split("\\.")).hasSize(5);
        assertThat(authorize(client, encrypted)).doesNotContain("error=");
    }

    /**
     * RFC 9101 section 6.3: the two client ids MUST be identical. With a signature that is a
     * formality; without one it is the only thing tying the object to the client.
     */
    @Test
    void anObjectNamingAnotherClientIsRefused() throws Exception {
        DemoProperties.Client client = properties.jarNoneClient();
        String impersonating = unsigned(client,
                Map.of("client_id", properties.client().clientId()));

        assertThat(refusal(client, impersonating))
                .contains("names client " + properties.client().clientId())
                .contains("the request names " + client.clientId());
    }

    /** The same rule applies to signed objects, where it has always been a formality. */
    @Test
    void theClientIdCheckAppliesToSignedObjectsToo() throws Exception {
        DemoProperties.Client client = properties.client();
        Map<String, String> parameters = parameters(client);
        parameters.put("client_id", properties.jarNoneClient().clientId());

        assertThat(refusal(client,
                signer.sign(client.clientId(), properties.issuerUri(), parameters)))
                .contains("names client " + properties.jarNoneClient().clientId());
    }

    /** RFC 9101 sections 4 and 10.5: a defence a client cannot read is one it cannot rely on. */
    @Test
    void bothSwitchesArePublishedInBothDocuments() throws Exception {
        for (String document : java.util.List.of("/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration")) {
            String metadata = mockMvc().perform(get(document))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();

            assertThat(metadata)
                    .contains(ServerMetadataCustomizer.REQUIRE_SIGNED_REQUEST_OBJECT_METADATA)
                    .contains(ServerMetadataCustomizer.REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED)
                    .contains("\"none\"");
        }
        assertThat(ServerMetadataCustomizer.REQUIRE_SIGNED_REQUEST_OBJECT)
                .as("false, so the page can show what the switch would otherwise prevent")
                .isFalse();
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jar-none")).andExpect(status().isOk());
    }

    private String setting(DemoProperties.Client client, String name) {
        RegisteredClient registered = registeredClients.findByClientId(client.clientId());
        assertThat(registered).isNotNull();
        Object value = registered.getClientSettings().getSetting(name);
        return value == null ? null : String.valueOf(value);
    }

    private String unsigned(DemoProperties.Client client, Map<String, String> overrides) {
        Map<String, String> parameters = parameters(client);
        parameters.putAll(overrides);
        return signer.unsigned(client.clientId(), properties.issuerUri(), parameters);
    }

    private String authorize(DemoProperties.Client client, String requestObject) throws Exception {
        MvcResult result = mockMvc().perform(get("/oauth2/authorize")
                        .queryParam("client_id", client.clientId())
                        .queryParam("request", requestObject)
                        .with(user("hendi")))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        return result.getResponse().getRedirectedUrl();
    }

    private String refusal(DemoProperties.Client client, String requestObject) throws Exception {
        MvcResult result = mockMvc().perform(get("/oauth2/authorize")
                        .queryParam("client_id", client.clientId())
                        .queryParam("request", requestObject)
                        .with(user("hendi")))
                .andExpect(status().isBadRequest())
                .andReturn();

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
