package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
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

import java.util.ArrayList;
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
 * Date: 19/09/26
 * Time: 08.20
 */
@SpringBootTest
class EncryptionMethodValuesTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private DemoProperties properties;

    @Autowired
    private JarRequestSigner signer;

    @Autowired
    private RSAKey requestDecryptionKey;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** The third of RFC 9101 section 4's lists, and the one this page is about. */
    @Test
    void theListIsPublishedAndMatchesWhatTheFilterDecrypts() throws Exception {
        String metadata = mockMvc().perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(metadata)
                .contains(ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED)
                .contains("A128CBC-HS256")
                .contains("A256GCM");
        assertThat(JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_METHODS)
                .containsExactlyInAnyOrder("A128CBC-HS256", "A256GCM");
    }

    /**
     * The two lists offer every pair between them; a client's registration names one. Four
     * combinations, one accepted, for each of two differently registered clients.
     */
    @Test
    void eachClientMayUseExactlyOneAdvertisedPair() throws Exception {
        for (DemoProperties.Client client : List.of(properties.client(), properties.jarGcmClient())) {
            List<String> accepted = new ArrayList<>();
            for (String alg : JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS) {
                for (String enc : JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_METHODS) {
                    MvcResult result = perform(client, encrypted(client, alg, enc));
                    if (result.getResponse().getStatus() == 302) {
                        accepted.add(alg + "/" + enc);
                    }
                }
            }
            assertThat(accepted).as("pairs %s may use", client.clientId()).hasSize(1);
        }
    }

    /**
     * And the pair each may use is the one it registered - with the method supplied where it
     * registered none, which for pkce-demo-client is both halves.
     */
    @Test
    void thePairIsTheRegisteredOne() throws Exception {
        DemoProperties.Client defaults = properties.client();
        assertThat(authorize(defaults, encrypted(defaults,
                JwtSecuredAuthorizationRequestFilter.DEFAULT_ENCRYPTION_ALG,
                JwtSecuredAuthorizationRequestFilter.DEFAULT_ENCRYPTION_ENC)))
                .doesNotContain("error=");

        DemoProperties.Client gcm = properties.jarGcmClient();
        assertThat(authorize(gcm, encrypted(gcm, "RSA-OAEP-256", "A256GCM")))
                .doesNotContain("error=");
    }

    /** The refusal says which half of the pair was wrong, which is two checks in sequence. */
    @Test
    void theRefusalNamesTheHalfThatDidNotMatch() throws Exception {
        DemoProperties.Client client = properties.client();

        assertThat(refusal(client, encrypted(client, "RSA-OAEP-256", "A256GCM")))
                .contains("content is encrypted with A256GCM");
        assertThat(refusal(client, encrypted(client, "RSA-OAEP-512", "A128CBC-HS256")))
                .contains("is encrypted with RSA-OAEP-512")
                .doesNotContain("content is encrypted");
    }

    /** A method on neither list, from the client that registered it: refused by the list. */
    @Test
    void aMethodOffTheListIsRefusedEvenWhenRegistered() throws Exception {
        DemoProperties.Client client = properties.jarUnsupportedEncClient();

        assertThat(JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_METHODS)
                .doesNotContain("A192CBC-HS384");
        assertThat(refusal(client, encrypted(client, "RSA-OAEP-256", "A192CBC-HS384")))
                .contains("does not decrypt A192CBC-HS384");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jar-enc-method-values")).andExpect(status().isOk());
    }

    private String encrypted(DemoProperties.Client client, String alg, String enc) {
        return signer.encrypt(
                signer.sign(client.clientId(), properties.issuerUri(), parameters(client)),
                requestDecryptionKey.toPublicJWK(), JWEAlgorithm.parse(alg),
                EncryptionMethod.parse(enc));
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
