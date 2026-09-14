package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.JarmController;
import id.my.hendisantika.oauth2pkcedemo.security.JarmResponseFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
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
 * Time: 14.20
 */
@SpringBootTest
class JarmAlgorithmTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private JWKSource<SecurityContext> jwkSource;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    private JarmResponseFilter filter() {
        return new JarmResponseFilter("/oauth2/authorize", registeredClientRepository, null,
                properties.issuerUri());
    }

    /** Three registrations that differ in one setting and in nothing else. */
    @Test
    void theRegistrationsCarryTheAlgorithmAsASetting() {
        assertThat(settingOf(properties.jarmClient())).isNull();
        assertThat(settingOf(properties.jarmEcClient())).isEqualTo("ES256");
        assertThat(settingOf(properties.jarmNoneClient())).isEqualTo("none");
    }

    /** JARM's default is RS256, and the two it cannot honour resolve to nothing at all. */
    @Test
    void theSettingResolvesToWhatTheServerCanSign() {
        assertThat(filter().algorithmFor(properties.jarmClient().clientId()))
                .isEqualTo(JarmResponseFilter.DEFAULT_ALGORITHM);
        assertThat(filter().algorithmFor(properties.jarmEcClient().clientId())).isEqualTo("ES256");
        assertThat(filter().algorithmFor(properties.jarmNoneClient().clientId())).isNull();
        assertThat(filter().algorithmFor("a-client-that-does-not-exist")).isNull();
    }

    /** Saying nothing still gets a signature, with the algorithm JARM defaults to. */
    @Test
    void aClientThatSaysNothingIsAnsweredWithRs256() throws Exception {
        String response = responseOf(properties.jarmClient());

        assertThat(response).isNotNull();
        assertThat(JWTParser.parse(response).getHeader().getAlgorithm().getName()).isEqualTo("RS256");
    }

    /** And a client that asked for ES256 is answered on the curve, by the other key. */
    @Test
    void aClientRegisteredForEs256IsAnsweredWithIt() throws Exception {
        String rsa = responseOf(properties.jarmClient());
        String ec = responseOf(properties.jarmEcClient());

        assertThat(JWTParser.parse(ec).getHeader().getAlgorithm().getName()).isEqualTo("ES256");
        // Different algorithms mean different keys, and the kid says which.
        assertThat(keyIdOf(ec)).isNotBlank().isNotEqualTo(keyIdOf(rsa));
    }

    /**
     * JARM forbids {@code none}. Handing such a client an unsigned response would be the quiet
     * failure the mode exists to prevent, so it is told instead - in the clear, because there is no
     * other way left to say it.
     */
    @Test
    void aRegistrationForNoneIsRefusedRatherThanDowngraded() throws Exception {
        String location = authorize(properties.jarmNoneClient());

        assertThat(parameterOf(location, JarmResponseFilter.RESPONSE)).isNull();
        assertThat(parameterOf(location, "error")).isEqualTo("invalid_request");
        assertThat(location).doesNotContain("code=");
    }

    /** Supporting ES256 meant having a key for it; the encoder cannot invent a curve. */
    @Test
    void theServerPublishesAKeyForEachAlgorithmItOffers() throws Exception {
        List<JWK> keys = jwkSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);

        assertThat(keys).hasSize(2);
        assertThat(keys).extracting(jwk -> jwk.getKeyType().getValue())
                .containsExactlyInAnyOrder("RSA", "EC");
        assertThat(JarmResponseFilter.SUPPORTED_ALGORITHMS).containsExactlyInAnyOrder("RS256", "ES256");
    }

    /** The second key changes nothing for ordinary tokens, which are still RS256. */
    @Test
    void theExtraKeyDoesNotChangeHowTokensAreSigned() throws Exception {
        MvcResult result = mockMvc().perform(org.springframework.test.web.servlet.request
                        .MockMvcRequestBuilders.post("/oauth2/token")
                        .header("Authorization", "Basic " + java.util.Base64.getEncoder()
                                .encodeToString((properties.exchangeClient().clientId() + ":"
                                        + properties.exchangeClient().clientSecret())
                                        .getBytes(StandardCharsets.UTF_8)))
                        .param("grant_type", "client_credentials")
                        .param("scope", "api.read"))
                .andExpect(status().isOk())
                .andReturn();

        Matcher token = Pattern.compile("\"access_token\":\"([^\"]+)\"")
                .matcher(result.getResponse().getContentAsString());
        assertThat(token.find()).isTrue();
        assertThat(JWTParser.parse(token.group(1)).getHeader().getAlgorithm().getName())
                .isEqualTo("RS256");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jarm-alg")).andExpect(status().isOk());
    }

    /** The kid off the header, which is how a client tells the two published keys apart. */
    private static String keyIdOf(String jwt) throws Exception {
        return String.valueOf(JWTParser.parse(jwt).getHeader().toJSONObject().get("kid"));
    }

    private String settingOf(DemoProperties.Client client) {
        RegisteredClient registered = registeredClientRepository.findByClientId(client.clientId());
        Object setting = registered.getClientSettings()
                .getSetting(JarmResponseFilter.SIGNED_RESPONSE_ALG);
        return setting == null ? null : String.valueOf(setting);
    }

    private String responseOf(DemoProperties.Client client) throws Exception {
        return parameterOf(authorize(client), JarmResponseFilter.RESPONSE);
    }

    private String authorize(DemoProperties.Client client) throws Exception {
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

        return result.getResponse().getRedirectedUrl();
    }

    private static String parameterOf(String uri, String name) {
        Matcher matcher = Pattern.compile("[?&]" + name + "=([^&]*)").matcher(uri);
        return matcher.find() ? URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8) : null;
    }
}
