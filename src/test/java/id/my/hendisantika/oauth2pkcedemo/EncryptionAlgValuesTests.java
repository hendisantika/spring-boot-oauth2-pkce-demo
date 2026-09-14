package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
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
 * Date: 18/09/26
 * Time: 20.25
 */
@SpringBootTest
class EncryptionAlgValuesTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private DemoProperties properties;

    @Autowired
    private JarRequestSigner signer;

    @Autowired
    private JWKSource<SecurityContext> jwkSource;

    @Autowired
    private RSAKey requestDecryptionKey;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** The list a client reads before deciding how to wrap anything. */
    @Test
    void theListIsPublishedAndMatchesWhatTheFilterUnwraps() throws Exception {
        String metadata = mockMvc().perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(metadata)
                .contains(ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED)
                .contains("RSA-OAEP-256")
                .contains("RSA-OAEP-512");
        assertThat(JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS)
                .containsExactlyInAnyOrder("RSA-OAEP-256", "RSA-OAEP-512");
    }

    /**
     * RFC 7517 section 4.2 makes "use" optional. With two RSA keys published, a client that had to
     * pick the encryption one by the absence of a marking would be guessing.
     */
    @Test
    void everyPublishedKeySaysWhatItIsFor() throws Exception {
        String published = mockMvc().perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(JWKSet.parse(published).getKeys())
                .hasSize(3)
                .allSatisfy(jwk -> {
                    assertThat(jwk.getKeyUse()).isNotNull();
                    assertThat(jwk.isPrivate()).isFalse();
                })
                .filteredOn(jwk -> KeyUse.ENCRYPTION == jwk.getKeyUse())
                .singleElement()
                .satisfies(jwk -> assertThat(jwk.getKeyID())
                        .isEqualTo(requestDecryptionKey.getKeyID()));
    }

    /** Advertised, registered, and addressed to the encryption key: unwrapped. */
    @Test
    void anAdvertisedAlgorithmToTheEncryptionKeyIsAccepted() throws Exception {
        DemoProperties.Client client = properties.client();

        assertThat(authorize(client, encrypted(client, JWEAlgorithm.RSA_OAEP_256,
                requestDecryptionKey))).doesNotContain("error=");
    }

    /**
     * The same object to the other RSA key. The refusal is honest and unhelpful, which is the
     * argument for publishing "use" rather than leaving a client to work it out.
     */
    @Test
    void theSameAlgorithmToTheSigningKeyIsRefused() throws Exception {
        DemoProperties.Client client = properties.client();
        RSAKey signingKey = signingKey();

        assertThat(signingKey.getKeyID()).isNotEqualTo(requestDecryptionKey.getKeyID());
        assertThat(refusal(client, encrypted(client, JWEAlgorithm.RSA_OAEP_256, signingKey)))
                .contains("could not be decrypted");
    }

    /** On the list, and not what this client registered. */
    @Test
    void anAdvertisedAlgorithmThisClientDidNotRegisterIsRefused() throws Exception {
        DemoProperties.Client client = properties.client();

        assertThat(refusal(client, encrypted(client, JWEAlgorithm.RSA_OAEP_512,
                requestDecryptionKey)))
                .contains("encrypted with RSA-OAEP-512")
                .contains("registered RSA-OAEP-256");
    }

    /** Registered by the client sending it, and not on the list. */
    @Test
    void anUnadvertisedAlgorithmIsRefusedEvenWhenRegistered() throws Exception {
        DemoProperties.Client client = properties.jarRsa15Client();

        assertThat(refusal(client, encrypted(client, JWEAlgorithm.RSA1_5, requestDecryptionKey)))
                .contains("does not decrypt RSA1_5");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jar-enc-alg-values")).andExpect(status().isOk());
    }

    private RSAKey signingKey() throws Exception {
        return jwkSource.get(new JWKSelector(new JWKMatcher.Builder()
                        .keyUse(KeyUse.SIGNATURE).keyType(com.nimbusds.jose.jwk.KeyType.RSA).build()),
                        null).stream()
                .map(RSAKey.class::cast)
                .findFirst()
                .orElseThrow();
    }

    private String encrypted(DemoProperties.Client client, JWEAlgorithm algorithm, RSAKey serverKey) {
        return signer.encrypt(
                signer.sign(client.clientId(), properties.issuerUri(), parameters(client)),
                serverKey.toPublicJWK(), algorithm);
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
