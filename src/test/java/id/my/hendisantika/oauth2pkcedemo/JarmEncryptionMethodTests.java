package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.JWEObject;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.JarmController;
import id.my.hendisantika.oauth2pkcedemo.security.JarmClientKeys;
import id.my.hendisantika.oauth2pkcedemo.security.JarmResponseFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
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
 * Time: 20.40
 */
@SpringBootTest
class JarmEncryptionMethodTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private JarmClientKeys clientKeys;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    private JarmResponseFilter filter() {
        return new JarmResponseFilter("/oauth2/authorize", registeredClientRepository, null,
                properties.issuerUri());
    }

    /** Absent means JARM's default; a method this server offers is taken as written. */
    @Test
    void theSettingResolvesToWhatTheServerOffers() {
        assertThat(filter().encryptionMethodFor(properties.jarmEncryptedClient().clientId()))
                .isEqualTo(JarmResponseFilter.DEFAULT_ENCRYPTION_METHOD);
        assertThat(filter().encryptionMethodFor(properties.jarmGcmClient().clientId()))
                .isEqualTo("A256GCM");
        assertThat(filter().encryptionMethodFor(properties.jarmUnsupportedEncClient().clientId()))
                .isNull();
        assertThat(JarmResponseFilter.SUPPORTED_ENCRYPTION_METHODS)
                .containsExactlyInAnyOrder("A128CBC-HS256", "A256GCM", "A128GCM");
    }

    /**
     * CBC works a block at a time, so the payload is padded up to a multiple of sixteen bytes, and
     * its IV is a full cipher block.
     */
    @Test
    void cbcPadsThePayloadAndTakesASixteenByteIv() throws Exception {
        String[] parts = responseOf(properties.jarmEncryptedClient()).split("\\.");
        String plaintext = clientKeys.decrypt(String.join(".", parts));

        assertThat(bytesOf(parts[2])).isEqualTo(16);
        assertThat(bytesOf(parts[3]) % 16).isZero();
        assertThat(bytesOf(parts[3])).isGreaterThan(plaintext.length());
        assertThat(bytesOf(parts[3]) - plaintext.length()).isBetween(1, 16);
    }

    /** GCM is a stream cipher: nothing is padded, and its IV is the twelve bytes it is defined for. */
    @Test
    void gcmPadsNothingAndTakesATwelveByteIv() throws Exception {
        String response = responseOf(properties.jarmGcmClient());
        String[] parts = response.split("\\.");
        String plaintext = clientKeys.decrypt(response);

        assertThat(JWEObject.parse(response).getHeader().getEncryptionMethod().getName())
                .isEqualTo("A256GCM");
        assertThat(bytesOf(parts[2])).isEqualTo(12);
        assertThat(bytesOf(parts[3])).isEqualTo(plaintext.length());
    }

    /** Both are authenticated, and the tag is the same size either way. */
    @Test
    void bothCarryASixteenByteTagAndTheSameWrappedKey() throws Exception {
        String[] cbc = responseOf(properties.jarmEncryptedClient()).split("\\.");
        String[] gcm = responseOf(properties.jarmGcmClient()).split("\\.");

        assertThat(bytesOf(cbc[4])).isEqualTo(16);
        assertThat(bytesOf(gcm[4])).isEqualTo(16);
        // alg never changed, and RSA-OAEP output is fixed by the modulus rather than its contents.
        assertThat(cbc[1].length()).isEqualTo(gcm[1].length());
    }

    /** Whatever the wrapping, the thing inside is the signed response and nothing else. */
    @Test
    void everyMethodCarriesTheSameKindOfPayload() throws Exception {
        for (DemoProperties.Client client :
                java.util.List.of(properties.jarmEncryptedClient(), properties.jarmGcmClient())) {
            assertThat(clientKeys.decrypt(responseOf(client)).split("\\."))
                    .as("payload for %s", client.clientId())
                    .hasSize(3);
        }
    }

    /** A method this server does not offer is refused rather than quietly replaced with one it does. */
    @Test
    void anUnsupportedMethodIsRefused() throws Exception {
        String location = authorize(properties.jarmUnsupportedEncClient());

        assertThat(parameterOf(location, JarmResponseFilter.RESPONSE)).isNull();
        assertThat(parameterOf(location, "error")).isEqualTo("invalid_request");
        assertThat(location).doesNotContain("code=");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jarm-enc-method")).andExpect(status().isOk());
    }

    /** Base64url without padding: four characters carry three bytes. */
    private static int bytesOf(String segment) {
        return segment.length() * 3 / 4;
    }

    private String responseOf(DemoProperties.Client client) throws Exception {
        String response = parameterOf(authorize(client), JarmResponseFilter.RESPONSE);
        assertThat(response).as("a JWE for %s", client.clientId()).isNotNull();
        return response;
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
