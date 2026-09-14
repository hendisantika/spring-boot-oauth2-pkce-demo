package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.jwk.RSAKey;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.service.RequestObjectEncryptionMethodService;
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
 * Time: 12.05
 */
@SpringBootTest
class RequestObjectEncryptionMethodTests extends AbstractMySqlIntegrationTest {

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

    /** The method travels as a client setting beside the algorithm, there being no field for either. */
    @Test
    void theClientsRegisterTheirMethods() {
        assertThat(setting(properties.jarGcmClient(),
                JwtSecuredAuthorizationRequestFilter.ENCRYPTION_ENC_SETTING)).isEqualTo("A256GCM");
        assertThat(setting(properties.jarUnsupportedEncClient(),
                JwtSecuredAuthorizationRequestFilter.ENCRYPTION_ENC_SETTING))
                .isEqualTo(RequestObjectEncryptionMethodService.UNSUPPORTED.getName());
        assertThat(setting(properties.client(),
                JwtSecuredAuthorizationRequestFilter.ENCRYPTION_ENC_SETTING))
                .as("registers nothing, and so is taken to have registered the spec's default")
                .isNull();
    }

    /** Each client encrypting with the method it registered is decrypted and acted on. */
    @Test
    void aRequestObjectMatchingTheRegistrationIsAccepted() throws Exception {
        assertThat(authorize(properties.client(),
                encrypted(properties.client(), EncryptionMethod.A128CBC_HS256)))
                .doesNotContain("error=");
        assertThat(authorize(properties.jarGcmClient(),
                encrypted(properties.jarGcmClient(), EncryptionMethod.A256GCM)))
                .doesNotContain("error=");
    }

    /** The default is the registration spec's own, so a client registering nothing still has one. */
    @Test
    void aMethodTheClientDidNotRegisterIsRefusedInEitherDirection() throws Exception {
        assertThat(JwtSecuredAuthorizationRequestFilter.DEFAULT_ENCRYPTION_ENC)
                .isEqualTo("A128CBC-HS256");

        assertThat(refusal(properties.client(),
                encrypted(properties.client(), EncryptionMethod.A256GCM)))
                .contains("invalid_request_object")
                .contains("encrypted with A256GCM")
                .contains("registered A128CBC-HS256");

        assertThat(refusal(properties.jarGcmClient(),
                encrypted(properties.jarGcmClient(), EncryptionMethod.A128CBC_HS256)))
                .contains("encrypted with A128CBC-HS256")
                .contains("registered A256GCM");
    }

    /** Refused rather than quietly downgraded to something this server does offer. */
    @Test
    void aMethodThisServerDoesNotOfferIsRefusedEvenWhenRegistered() throws Exception {
        DemoProperties.Client client = properties.jarUnsupportedEncClient();

        assertThat(JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_METHODS)
                .doesNotContain(RequestObjectEncryptionMethodService.UNSUPPORTED.getName());
        assertThat(refusal(client,
                encrypted(client, RequestObjectEncryptionMethodService.UNSUPPORTED)))
                .contains("does not decrypt A192CBC-HS384");
    }

    /**
     * The registration spec: when request_object_encryption_enc is included,
     * request_object_encryption_alg must be too. A registration missing half of the pair is one
     * this server will not fill in for itself.
     */
    @Test
    void aMethodRegisteredWithNoAlgorithmIsRefused() throws Exception {
        DemoProperties.Client client = properties.jarEncOnlyClient();

        assertThat(setting(client, JwtSecuredAuthorizationRequestFilter.ENCRYPTION_ALG_SETTING))
                .isNull();
        assertThat(setting(client, JwtSecuredAuthorizationRequestFilter.ENCRYPTION_ENC_SETTING))
                .isEqualTo("A256GCM");
        assertThat(refusal(client, encrypted(client, EncryptionMethod.A256GCM)))
                .contains("registered A256GCM and no algorithm");
    }

    /**
     * CBC pads up to a block boundary and GCM does not, which is the only part of the choice
     * visible from outside the encryption.
     */
    @Test
    void cbcPadsAndGcmDoesNot() throws Exception {
        String signed = signer.sign(properties.client().clientId(), properties.issuerUri(),
                parameters(properties.client()));

        JWEObject cbc = JWEObject.parse(signer.encrypt(signed, requestDecryptionKey.toPublicJWK(),
                JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256));
        JWEObject gcm = JWEObject.parse(signer.encrypt(signed, requestDecryptionKey.toPublicJWK(),
                JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM));

        assertThat(cbc.getHeader().getAlgorithm()).isEqualTo(gcm.getHeader().getAlgorithm());
        assertThat(cbc.getIV().decode()).hasSize(16);
        assertThat(gcm.getIV().decode()).hasSize(12);
        assertThat(cbc.getAuthTag().decode()).hasSize(16);
        assertThat(gcm.getAuthTag().decode()).hasSize(16);
        assertThat(gcm.getCipherText().decode())
                .as("a stream cipher, so exactly as long as what went in")
                .hasSize(signed.length());
        assertThat(cbc.getCipherText().decode().length)
                .as("padded up to the next block boundary")
                .isGreaterThan(signed.length());
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jar-enc-method")).andExpect(status().isOk());
    }

    private String setting(DemoProperties.Client client, String name) {
        RegisteredClient registered = registeredClients.findByClientId(client.clientId());
        assertThat(registered).isNotNull();
        Object value = registered.getClientSettings().getSetting(name);
        return value == null ? null : String.valueOf(value);
    }

    private String encrypted(DemoProperties.Client client, EncryptionMethod method) {
        return signer.encrypt(
                signer.sign(client.clientId(), properties.issuerUri(), parameters(client)),
                requestDecryptionKey.toPublicJWK(), JWEAlgorithm.RSA_OAEP_256, method);
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
