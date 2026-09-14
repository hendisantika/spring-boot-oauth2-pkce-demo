package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
 * Time: 06.10
 */
@SpringBootTest
class RequestObjectSigningAlgTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private JarRequestSigner signer;

    @Autowired
    private DemoProperties properties;

    @Autowired
    private RegisteredClientRepository registeredClients;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** RFC 9101 section 10.1: the algorithm is registered, and here it travels as a client setting. */
    @Test
    void thePs256ClientRegistersItsAlgorithm() {
        RegisteredClient ps256 = registeredClients.findByClientId(properties.jarPsClient().clientId());
        assertThat(ps256).isNotNull();
        assertThat(ps256.getClientSettings()
                .<Object>getSetting(JwtSecuredAuthorizationRequestFilter.SIGNING_ALG_SETTING))
                .isEqualTo("PS256");

        RegisteredClient other = registeredClients.findByClientId(properties.client().clientId());
        assertThat(other.getClientSettings()
                .<Object>getSetting(JwtSecuredAuthorizationRequestFilter.SIGNING_ALG_SETTING))
                .as("registers nothing, and so is taken to have registered the default")
                .isNull();
    }

    /** One RSA key, either padding - which is what makes the registration worth having. */
    @Test
    void theSameKeySignsBothAlgorithms() throws ParseException {
        DemoProperties.Client client = properties.client();

        for (JWSAlgorithm algorithm : java.util.List.of(JWSAlgorithm.RS256, JWSAlgorithm.PS256)) {
            SignedJWT jwt = SignedJWT.parse(signer.sign(client.clientId(), properties.issuerUri(),
                    parameters(client), algorithm));

            assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(algorithm);
            assertThat(jwt.getHeader().getKeyID())
                    .as("the same key for both")
                    .isEqualTo(SignedJWT.parse(signer.sign(client.clientId(), properties.issuerUri(),
                            parameters(client))).getHeader().getKeyID());
        }
    }

    /** Each client signing with what it registered is acted on. */
    @Test
    void aRequestObjectMatchingTheRegistrationIsAccepted() throws Exception {
        assertThat(authorize(properties.client(), signed(properties.client(), JWSAlgorithm.RS256)))
                .doesNotContain("error=");
        assertThat(authorize(properties.jarPsClient(),
                signed(properties.jarPsClient(), JWSAlgorithm.PS256)))
                .doesNotContain("error=");
    }

    /**
     * A valid signature, refused for being the wrong algorithm. The question is not whether the
     * signature verifies but whether this client agreed in advance to sign this way.
     */
    @Test
    void aClientSigningWithAnAlgorithmItDidNotRegisterIsRefused() throws Exception {
        assertThat(refusal(properties.client(), signed(properties.client(), JWSAlgorithm.PS256)))
                .contains("invalid_request_object")
                .contains("signed with PS256")
                .contains("registered RS256");
    }

    /** And the other way round, which is the half a permissive server would let through. */
    @Test
    void theRuleAlsoRefusesTheDefaultAlgorithmFromAClientThatRegisteredPs256() throws Exception {
        assertThat(refusal(properties.jarPsClient(),
                signed(properties.jarPsClient(), JWSAlgorithm.RS256)))
                .contains("signed with RS256")
                .contains("registered PS256");
    }

    /**
     * {@code none} is compared like any other registered algorithm: this client registered RS256, so
     * an unsigned object is refused for being unsigned, not for being unparseable.
     */
    @Test
    void anUnsignedRequestObjectIsRefusedByTheSameComparison() throws Exception {
        String unsigned = signer.unsigned(properties.client().clientId(), properties.issuerUri(),
                parameters(properties.client()));

        assertThat(JWTParser.parse(unsigned)).isInstanceOf(PlainJWT.class);
        assertThatThrownBy(() -> SignedJWT.parse(unsigned)).isInstanceOf(ParseException.class);
        assertThat(refusal(properties.client(), unsigned))
                .contains("signed with none")
                .contains("registered RS256");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jar-alg")).andExpect(status().isOk());
    }

    private String signed(DemoProperties.Client client, JWSAlgorithm algorithm) {
        return signer.sign(client.clientId(), properties.issuerUri(), parameters(client), algorithm);
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
