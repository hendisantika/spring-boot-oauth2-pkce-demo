package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 17.15
 */
@SpringBootTest
class JwtSecuredAuthorizationRequestTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private JarRequestSigner jarRequestSigner;

    @Autowired
    private AuthorizationServerSettings settings;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    private Map<String, String> parameters() {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("response_type", "code");
        parameters.put("client_id", properties.client().clientId());
        parameters.put("redirect_uri", properties.issuerUri() + "/login/oauth2/code/"
                + properties.client().registrationId());
        parameters.put("scope", "openid profile");
        parameters.put("state", "jar-test");
        parameters.put("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        parameters.put("code_challenge_method", "S256");
        return parameters;
    }

    @Test
    void aRequestObjectIsTypedAndNamesTheClientAndTheServer() throws Exception {
        String requestObject = jarRequestSigner.sign(properties.client().clientId(),
                properties.issuerUri(), parameters());

        var jwt = JWTParser.parse(requestObject);
        // RFC 9101 section 10.8: the explicit type stops a JWT minted elsewhere being passed off as
        // an authorization request.
        assertThat(jwt.getHeader().getType().toString())
                .isEqualTo(JwtSecuredAuthorizationRequestFilter.REQUEST_OBJECT_TYPE);
        assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo(properties.client().clientId());
        // Audience is this server, so the object cannot be replayed at another.
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly(properties.issuerUri());
        assertThat(jwt.getJWTClaimsSet().getExpirationTime()).isNotNull();
    }

    @Test
    void theClientPublishesOnlyItsPublicKey() throws Exception {
        MvcResult result = mockMvc().perform(get("/jar-jwks.json"))
                .andExpect(status().isOk())
                .andReturn();

        JWKSet jwkSet = JWKSet.parse(result.getResponse().getContentAsString());
        assertThat(jwkSet.getKeys()).hasSize(1);
        assertThat(result.getResponse().getContentAsString())
                .doesNotContain("\"d\":").doesNotContain("\"p\":");
    }

    @Test
    void aValidRequestObjectIsActedOn() throws Exception {
        MvcResult result = mockMvc().perform(get(settings.getAuthorizationEndpoint())
                        .param("client_id", properties.client().clientId())
                        .param(JwtSecuredAuthorizationRequestFilter.REQUEST,
                                jarRequestSigner.sign(properties.client().clientId(),
                                        properties.issuerUri(), parameters())))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        // Not rejected: parked at the login page like any other valid authorization request.
        assertThat(result.getResponse().getRedirectedUrl()).endsWith("/login");
    }

    @Test
    void anObjectSignedByAnotherKeyIsRejected() throws Exception {
        MvcResult result = mockMvc().perform(get(settings.getAuthorizationEndpoint())
                        .param("client_id", properties.client().clientId())
                        .param(JwtSecuredAuthorizationRequestFilter.REQUEST,
                                jarRequestSigner.signWithAnotherKey(properties.client().clientId(),
                                        properties.issuerUri(), parameters())))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).contains("invalid_request_object");
    }

    @Test
    void anObjectForAnotherAudienceIsRejected() throws Exception {
        MvcResult result = mockMvc().perform(get(settings.getAuthorizationEndpoint())
                        .param("client_id", properties.client().clientId())
                        .param(JwtSecuredAuthorizationRequestFilter.REQUEST,
                                jarRequestSigner.sign(properties.client().clientId(),
                                        "https://another-authorization-server.example", parameters())))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).contains("another audience");
    }

    @Test
    void somethingThatIsNotAJwtIsRejected() throws Exception {
        mockMvc().perform(get(settings.getAuthorizationEndpoint())
                        .param("client_id", properties.client().clientId())
                        .param(JwtSecuredAuthorizationRequestFilter.REQUEST, "not-a-jwt"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void theJarPageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jar")).andExpect(status().isOk());
    }
}
