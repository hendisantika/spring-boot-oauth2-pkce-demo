package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
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
 * Date: 15/09/26
 * Time: 23.40
 */
@SpringBootTest
class RequestObjectEncryptionTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private JarRequestSigner signer;

    @Autowired
    private RSAKey requestDecryptionKey;

    @Autowired
    private JWKSource<SecurityContext> jwkSource;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /**
     * The server publishes a key marked for encryption, separate from the two it signs with - and
     * publishes only the public halves, which is the part that matters. The source behind the
     * endpoint holds the private ones; the endpoint is where they must not appear.
     */
    @Test
    void theServerPublishesAnEncryptionKeyOfItsOwn() throws Exception {
        assertThat(jwkSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null))
                .hasSize(3)
                .filteredOn(jwk -> KeyUse.ENCRYPTION == jwk.getKeyUse())
                .singleElement()
                .satisfies(jwk -> assertThat(jwk.getKeyID()).isEqualTo(requestDecryptionKey.getKeyID()));

        MvcResult result = mockMvc().perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andReturn();

        String published = result.getResponse().getContentAsString();
        assertThat(published).contains(requestDecryptionKey.getKeyID()).contains("\"use\":\"enc\"");
        assertThat(JWKSet.parse(published).getKeys()).hasSize(3)
                .allSatisfy(jwk -> assertThat(jwk.isPrivate()).isFalse());
    }

    /** RFC 9101 section 6.2: signed first, encrypted second, with the JWT type marked inside. */
    @Test
    void theClientSignsThenEncrypts() throws Exception {
        String encrypted = signer.signAndEncrypt(properties.client().clientId(),
                properties.issuerUri(), parameters(), requestDecryptionKey.toPublicJWK());

        assertThat(encrypted.split("\\.")).hasSize(5);
        JWEObject jwe = JWEObject.parse(encrypted);
        assertThat(jwe.getHeader().getAlgorithm().getName()).isEqualTo("RSA-OAEP-256");
        assertThat(jwe.getHeader().getContentType()).isEqualTo("JWT");
        assertThat(jwe.getHeader().getKeyID()).isEqualTo(requestDecryptionKey.getKeyID());
    }

    /** A signed object hands every claim to anyone holding the URL; an encrypted one hands none. */
    @Test
    void onlyTheSignedFormIsReadableWithoutAKey() throws Exception {
        Map<String, String> parameters = parameters();
        String signed = signer.sign(properties.client().clientId(), properties.issuerUri(), parameters);

        assertThat(SignedJWT.parse(signed).getJWTClaimsSet().getClaim("login_hint"))
                .isEqualTo(parameters.get("login_hint"));
        // The encrypted one cannot even be parsed as a signed JWT.
        String encrypted = signer.encrypt(signed, requestDecryptionKey.toPublicJWK());
        assertThat(encrypted).doesNotContain(SignedJWT.parse(signed).getPayload().toBase64URL().toString());
    }

    /** Decrypted or not, the server acts on the same request. */
    @Test
    void bothFormsAreActedOn() throws Exception {
        Map<String, String> parameters = parameters();
        String signed = signer.sign(properties.client().clientId(), properties.issuerUri(), parameters);

        for (String requestObject :
                List.of(signed, signer.encrypt(signed, requestDecryptionKey.toPublicJWK()))) {
            String location = authorize(requestObject);

            assertThat(location).as("where %s parts went", requestObject.split("\\.").length)
                    .doesNotContain("error=");
            assertThat(location).contains("/oauth2/consent");
        }
    }

    /**
     * Encryption says nobody else read it, not who wrote it - so the signature is checked all the
     * same, and a request object signed by the wrong key is refused after decrypting.
     */
    @Test
    void theSignatureIsStillCheckedInsideTheEncryption() throws Exception {
        String wronglySigned = signer.signWithAnotherKey(properties.client().clientId(),
                properties.issuerUri(), parameters());

        MvcResult result = mockMvc().perform(get("/oauth2/authorize")
                        .queryParam("client_id", properties.client().clientId())
                        .queryParam("request", signer.encrypt(wronglySigned,
                                requestDecryptionKey.toPublicJWK()))
                        .with(user("hendi")))
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).contains("invalid_request_object");
    }

    /** Addressed to somebody else, and there is nothing to do with it but say so. */
    @Test
    void anObjectEncryptedToAnotherKeyIsRefused() throws Exception {
        String signed = signer.sign(properties.client().clientId(), properties.issuerUri(), parameters());
        RSAKey strangers = new RSAKeyGenerator(2048).keyID("somebody-elses-key").generate();

        MvcResult result = mockMvc().perform(get("/oauth2/authorize")
                        .queryParam("client_id", properties.client().clientId())
                        .queryParam("request", signer.encrypt(signed, strangers.toPublicJWK()))
                        .with(user("hendi")))
                .andReturn();

        assertThat(result.getResponse().getContentAsString())
                .contains("could not be decrypted");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jar-enc")).andExpect(status().isOk());
    }

    private String authorize(String requestObject) throws Exception {
        MvcResult result = mockMvc().perform(get("/oauth2/authorize")
                        .queryParam("client_id", properties.client().clientId())
                        .queryParam("request", requestObject)
                        .with(user("hendi")))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        return result.getResponse().getRedirectedUrl();
    }

    private Map<String, String> parameters() {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("response_type", "code");
        parameters.put("client_id", properties.client().clientId());
        parameters.put("scope", String.join(" ", properties.client().scopes()));
        parameters.put("redirect_uri", properties.issuerUri() + "/login/oauth2/code/"
                + properties.client().registrationId());
        parameters.put("state", "a-state");
        parameters.put("code_challenge", CODE_CHALLENGE);
        parameters.put("code_challenge_method", "S256");
        parameters.put("login_hint", "hendi@example.com");
        return parameters;
    }
}
