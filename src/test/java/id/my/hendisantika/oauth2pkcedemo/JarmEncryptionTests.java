package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.JarmClientJwkSetController;
import id.my.hendisantika.oauth2pkcedemo.controller.JarmController;
import id.my.hendisantika.oauth2pkcedemo.security.JarmClientKeys;
import id.my.hendisantika.oauth2pkcedemo.security.JarmResponseFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
 * Time: 17.05
 */
@SpringBootTest
class JarmEncryptionTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private JarmClientKeys clientKeys;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** The registration names the algorithm and where the client publishes the key for it. */
    @Test
    void theRegistrationNamesTheAlgorithmAndTheClientsKeys() {
        RegisteredClient client = registeredClientRepository
                .findByClientId(properties.jarmEncryptedClient().clientId());

        assertThat(client.getClientSettings()
                .<Object>getSetting(JarmResponseFilter.ENCRYPTED_RESPONSE_ALG))
                .isEqualTo("RSA-OAEP-256");
        // enc is deliberately absent, so the default has something to do.
        assertThat(client.getClientSettings()
                .<Object>getSetting(JarmResponseFilter.ENCRYPTED_RESPONSE_ENC)).isNull();
        assertThat(client.getClientSettings().getJwkSetUrl())
                .isEqualTo(properties.issuerUri() + JarmClientJwkSetController.JARM_CLIENT_JWK_SET_URI);
    }

    /** A signed response is base64, not ciphertext: the code is there for anyone holding the URL. */
    @Test
    void aSignedOnlyResponseIsReadableByAnybody() throws Exception {
        String response = responseOf(properties.jarmClient());

        assertThat(response.split("\\.")).hasSize(3);
        assertThat(JWTParser.parse(response).getJWTClaimsSet().getClaim("code")).isNotNull();
    }

    /** With encryption registered, the same answer arrives as a JWE and gives nothing away. */
    @Test
    void anEncryptedResponseIsAJweAndSaysNothing() throws Exception {
        String response = responseOf(properties.jarmEncryptedClient());

        assertThat(response.split("\\.")).hasSize(5);
        JWEObject jwe = JWEObject.parse(response);
        assertThat(jwe.getHeader().getAlgorithm().getName()).isEqualTo("RSA-OAEP-256");
        // JARM defaults the method when only the algorithm is registered.
        assertThat(jwe.getHeader().getEncryptionMethod().getName())
                .isEqualTo(JarmResponseFilter.DEFAULT_ENCRYPTION_METHOD);
        // RFC 7519 section 5.2: cty says there is another JWT inside.
        assertThat(jwe.getHeader().getContentType()).isEqualTo("JWT");
        assertThat(jwe.getHeader().getKeyID()).isEqualTo(clientKeys.keyId());
    }

    /**
     * Signed then encrypted, in that order: decrypting reveals the signed response intact, and its
     * signature still verifies - the encryption was wrapped around it, not applied to it.
     */
    @Test
    void decryptingRevealsTheSignedResponseUnchanged() throws Exception {
        String nested = clientKeys.decrypt(responseOf(properties.jarmEncryptedClient()));

        assertThat(nested.split("\\.")).hasSize(3);
        var jwt = jwtDecoder.decode(nested);
        assertThat(jwt.getClaimAsString("code")).isNotBlank();
        assertThat(jwt.getClaimAsString("iss")).isEqualTo(properties.issuerUri());
        assertThat(jwt.getAudience())
                .containsExactly(properties.jarmEncryptedClient().clientId());
    }

    /** The client publishes only the public half, which is all the server needs. */
    @Test
    void theClientPublishesOnlyThePublicHalf() throws Exception {
        MvcResult result = mockMvc()
                .perform(get(JarmClientJwkSetController.JARM_CLIENT_JWK_SET_URI))
                .andExpect(status().isOk())
                .andReturn();

        String jwks = result.getResponse().getContentAsString();
        assertThat(jwks).contains(clientKeys.keyId()).contains("\"use\":\"enc\"");
        // The private exponent and the primes stay at home.
        assertThat(jwks).doesNotContain("\"d\"").doesNotContain("\"p\"").doesNotContain("\"q\"");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jarm-enc")).andExpect(status().isOk());
    }

    private String responseOf(DemoProperties.Client client) throws Exception {
        MvcResult result = mockMvc().perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", client.clientId())
                        .queryParam("scope", String.join(" ", client.scopes()))
                        .queryParam("redirect_uri", properties.issuerUri() + JarmController.CALLBACK_URI)
                        .queryParam("state", "a-state")
                        .queryParam("code_challenge", CODE_CHALLENGE)
                        .queryParam("code_challenge_method", "S256")
                        .queryParam(JarmResponseFilter.RESPONSE_MODE, "jwt")
                        .with(user("hendi")))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        Matcher matcher = Pattern.compile("[?&]response=([^&]*)")
                .matcher(result.getResponse().getRedirectedUrl());
        assertThat(matcher.find()).isTrue();
        return URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8);
    }
}
