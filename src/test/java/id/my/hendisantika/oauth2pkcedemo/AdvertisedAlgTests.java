package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.SignedJWT;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import id.my.hendisantika.oauth2pkcedemo.service.AdvertisedAlgService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.text.ParseException;
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
 * Date: 18/09/26
 * Time: 15.10
 */
@SpringBootTest
class AdvertisedAlgTests extends AbstractMySqlIntegrationTest {

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

    /** RFC 9101 section 4 names three lists, and all three are now in both documents. */
    @Test
    void allThreeListsArePublished() throws Exception {
        for (String document : List.of("/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration")) {
            String metadata = mockMvc().perform(get(document))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();

            assertThat(metadata)
                    .contains(ServerMetadataCustomizer.REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED)
                    .contains(ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED)
                    .contains(ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED)
                    .contains("\"none\"")
                    .contains("RSA-OAEP-512")
                    .contains("A256GCM");
        }
    }

    /** Published from the constants the filter enforces, so the document cannot drift from the code. */
    @Test
    void theListsAreTheOnesTheFilterUses() {
        assertThat(new java.util.TreeSet<>(
                JwtSecuredAuthorizationRequestFilter.SUPPORTED_SIGNING_ALGS))
                .containsExactly("PS256", "RS256", "none");
        assertThat(AdvertisedAlgService.METADATA_NAMES).hasSize(3);
    }

    /** The client publishes a key for each family, so a refusal is never about a missing key. */
    @Test
    void theClientPublishesBothKinds() throws ParseException {
        JWKSet published = JWKSet.parse(signer.publicJwkSetJson());

        assertThat(published.getKeys()).hasSize(2)
                .allSatisfy(jwk -> assertThat(jwk.isPrivate()).isFalse());
        assertThat(published.getKeys().stream().map(jwk -> jwk.getKeyType()).toList())
                .containsExactlyInAnyOrder(KeyType.RSA, KeyType.EC);
    }

    /** On the list and registered by this client: acted on. */
    @Test
    void anAdvertisedAlgorithmTheClientRegisteredIsAccepted() throws Exception {
        DemoProperties.Client client = properties.client();

        assertThat(authorize(client, signer.sign(client.clientId(), properties.issuerUri(),
                parameters(client), JWSAlgorithm.RS256))).doesNotContain("error=");
    }

    /** On the list and registered by somebody else: refused. The list is the server's. */
    @Test
    void anAdvertisedAlgorithmThisClientDidNotRegisterIsRefused() throws Exception {
        DemoProperties.Client client = properties.client();

        assertThat(refusal(client, signer.sign(client.clientId(), properties.issuerUri(),
                parameters(client), JWSAlgorithm.PS256)))
                .contains("signed with PS256")
                .contains("registered RS256");
    }

    /**
     * Registered, correctly signed, on a key the client publishes - and not on the list, which is
     * the only reason it is refused.
     */
    @Test
    void anUnadvertisedAlgorithmIsRefusedEvenWhenRegistered() throws Exception {
        DemoProperties.Client client = properties.jarEsClient();
        RegisteredClient registered = registeredClients.findByClientId(client.clientId());

        assertThat(registered).isNotNull();
        assertThat(registered.getClientSettings()
                .<Object>getSetting(JwtSecuredAuthorizationRequestFilter.SIGNING_ALG_SETTING))
                .isEqualTo("ES256");
        assertThat(JwtSecuredAuthorizationRequestFilter.SUPPORTED_SIGNING_ALGS)
                .doesNotContain("ES256");

        String requestObject = signer.signWithEllipticCurve(client.clientId(),
                properties.issuerUri(), parameters(client));
        assertThat(SignedJWT.parse(requestObject).getHeader().getAlgorithm())
                .isEqualTo(JWSAlgorithm.ES256);
        assertThat(refusal(client, requestObject))
                .contains("does not check ES256 signatures");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jar-alg-values")).andExpect(status().isOk());
    }

    private MvcResult perform(DemoProperties.Client client, String requestObject) throws Exception {
        return mockMvc().perform(get("/oauth2/authorize")
                        .queryParam("client_id", client.clientId())
                        .queryParam("request", requestObject)
                        .with(user("hendi")))
                .andReturn();
    }

    private String authorize(DemoProperties.Client client, String requestObject) throws Exception {
        MvcResult result = perform(client, requestObject);
        assertThat(result.getResponse().getStatus()).isEqualTo(302);
        return result.getResponse().getRedirectedUrl();
    }

    private String refusal(DemoProperties.Client client, String requestObject) throws Exception {
        MvcResult result = perform(client, requestObject);
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
