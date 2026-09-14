package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.jwk.RSAKey;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
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
 * Time: 09.20
 */
@SpringBootTest
class RequestObjectEncryptionAlgTests extends AbstractMySqlIntegrationTest {

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

    /** The declared algorithm travels as a client setting, there being no field for it. */
    @Test
    void theTwoClientsRegisterTheirAlgorithms() {
        assertThat(registeredFor(properties.jarOaep512Client())).isEqualTo("RSA-OAEP-512");
        assertThat(registeredFor(properties.jarRsa15Client())).isEqualTo("RSA1_5");
        assertThat(registeredFor(properties.client()))
                .as("registers nothing, and so is taken to have registered the default")
                .isNull();
    }

    /** One server key, either wrapping - which is what makes the registration worth having. */
    @Test
    void theSameServerKeyWrapsBothAlgorithms() throws ParseException {
        String signed = signer.sign(properties.client().clientId(), properties.issuerUri(),
                parameters(properties.client()));

        for (JWEAlgorithm algorithm : java.util.List.of(JWEAlgorithm.RSA_OAEP_256,
                JWEAlgorithm.RSA_OAEP_512, JWEAlgorithm.RSA1_5)) {
            JWEObject jwe = JWEObject.parse(
                    signer.encrypt(signed, requestDecryptionKey.toPublicJWK(), algorithm));

            assertThat(jwe.getHeader().getAlgorithm()).isEqualTo(algorithm);
            assertThat(jwe.getHeader().getKeyID()).isEqualTo(requestDecryptionKey.getKeyID());
            assertThat(jwe.getHeader().getContentType()).isEqualTo("JWT");
        }
    }

    /** Each client wrapping with what it registered is unwrapped and acted on. */
    @Test
    void aRequestObjectMatchingTheRegistrationIsAccepted() throws Exception {
        assertThat(authorize(properties.client(),
                encrypted(properties.client(), JWEAlgorithm.RSA_OAEP_256)))
                .doesNotContain("error=");
        assertThat(authorize(properties.jarOaep512Client(),
                encrypted(properties.jarOaep512Client(), JWEAlgorithm.RSA_OAEP_512)))
                .doesNotContain("error=");
    }

    /**
     * Stricter than the registration spec, which says in as many words that the client may still
     * use any other algorithm the server supports. Both of these would be legal read literally.
     */
    @Test
    void anAlgorithmTheClientDidNotRegisterIsRefusedInEitherDirection() throws Exception {
        assertThat(refusal(properties.client(),
                encrypted(properties.client(), JWEAlgorithm.RSA_OAEP_512)))
                .contains("invalid_request_object")
                .contains("encrypted with RSA-OAEP-512")
                .contains("registered RSA-OAEP-256");

        assertThat(refusal(properties.jarOaep512Client(),
                encrypted(properties.jarOaep512Client(), JWEAlgorithm.RSA_OAEP_256)))
                .contains("encrypted with RSA-OAEP-256")
                .contains("registered RSA-OAEP-512");
    }

    /**
     * Matching the registration is necessary, not sufficient: a registration cannot add an
     * algorithm to a server, and RSA1_5 is left out of the supported set on purpose.
     */
    @Test
    void anAlgorithmThisServerDoesNotImplementIsRefusedEvenWhenRegistered() throws Exception {
        DemoProperties.Client client = properties.jarRsa15Client();

        assertThat(registeredFor(client)).isEqualTo(JWEAlgorithm.RSA1_5.getName());
        assertThat(JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS)
                .doesNotContain(JWEAlgorithm.RSA1_5.getName());
        assertThat(refusal(client, encrypted(client, JWEAlgorithm.RSA1_5)))
                .contains("does not decrypt RSA1_5");
    }

    /**
     * Where the spec is followed rather than departed from: registering an algorithm says how a
     * client will encrypt, not that it must.
     */
    @Test
    void aClientThatRegisteredAnAlgorithmMayStillSendAnUnencryptedRequestObject() throws Exception {
        DemoProperties.Client client = properties.jarOaep512Client();
        String signedOnly = signer.sign(client.clientId(), properties.issuerUri(), parameters(client));

        assertThat(signedOnly.split("\\.")).hasSize(3);
        assertThat(authorize(client, signedOnly)).doesNotContain("error=");
    }

    /** Unwrapped or not, the signature is still checked against the client's published key. */
    @Test
    void theSignatureIsStillCheckedInsideTheNewAlgorithms() throws Exception {
        DemoProperties.Client client = properties.jarOaep512Client();
        String wronglySigned = signer.signWithAnotherKey(client.clientId(), properties.issuerUri(),
                parameters(client));

        assertThat(refusal(client, signer.encrypt(wronglySigned, requestDecryptionKey.toPublicJWK(),
                JWEAlgorithm.RSA_OAEP_512)))
                .contains("signature does not verify");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jar-enc-alg")).andExpect(status().isOk());
    }

    private String registeredFor(DemoProperties.Client client) {
        RegisteredClient registered = registeredClients.findByClientId(client.clientId());
        assertThat(registered).isNotNull();
        Object setting = registered.getClientSettings()
                .getSetting(JwtSecuredAuthorizationRequestFilter.ENCRYPTION_ALG_SETTING);
        return setting == null ? null : String.valueOf(setting);
    }

    private String encrypted(DemoProperties.Client client, JWEAlgorithm algorithm) {
        return signer.encrypt(
                signer.sign(client.clientId(), properties.issuerUri(), parameters(client)),
                requestDecryptionKey.toPublicJWK(), algorithm);
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
