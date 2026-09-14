package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.IntrospectionJwtResponseHandler;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 08.15
 */
@SpringBootTest
class IntrospectionJwtTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** A caller that asks for nothing in particular gets exactly what it always did. */
    @Test
    void withoutAskingTheResponseIsStillPlainJson() throws Exception {
        MvcResult result = introspect(accessToken(), MediaType.APPLICATION_JSON_VALUE);

        assertThat(result.getResponse().getContentType()).contains(MediaType.APPLICATION_JSON_VALUE);
        assertThat(result.getResponse().getContentAsString()).contains("\"active\":true");
    }

    /** RFC 9701: the same answer as a JWT, typed, issued, and addressed to the caller. */
    @Test
    void askingForTheJwtFormGetsASignedResponse() throws Exception {
        MvcResult result = introspect(accessToken(), IntrospectionJwtResponseHandler.JWT_MEDIA_TYPE);

        assertThat(result.getResponse().getContentType())
                .contains(IntrospectionJwtResponseHandler.JWT_MEDIA_TYPE);
        var jwt = JWTParser.parse(result.getResponse().getContentAsString());
        assertThat(jwt.getHeader().getType().toString())
                .isEqualTo(IntrospectionJwtResponseHandler.JWT_TYPE);
        assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo(properties.issuerUri());
        assertThat(jwt.getJWTClaimsSet().getAudience())
                .containsExactly(properties.exchangeClient().clientId());

        Map<String, Object> introspection = jwt.getJWTClaimsSet()
                .getJSONObjectClaim(IntrospectionJwtResponseHandler.TOKEN_INTROSPECTION);
        assertThat(introspection).containsEntry("active", true);
        // RFC 7662 shapes: numeric dates, and one space-delimited scope string.
        assertThat(introspection.get("exp")).isInstanceOf(Number.class);
        assertThat(introspection.get("scope")).isInstanceOf(String.class);
    }

    /** The answer is addressed to whoever asked, so two callers get answers that are not swappable. */
    @Test
    void eachCallerIsNamedAsTheAudience() throws Exception {
        String token = accessToken();

        MvcResult mine = introspect(token, IntrospectionJwtResponseHandler.JWT_MEDIA_TYPE);
        MvcResult theirs = introspect(token, IntrospectionJwtResponseHandler.JWT_MEDIA_TYPE,
                properties.relayClient());

        assertThat(JWTParser.parse(mine.getResponse().getContentAsString())
                .getJWTClaimsSet().getAudience())
                .containsExactly(properties.exchangeClient().clientId());
        assertThat(JWTParser.parse(theirs.getResponse().getContentAsString())
                .getJWTClaimsSet().getAudience())
                .containsExactly(properties.relayClient().clientId());
    }

    /** A signed "no" is a statement too, and it is signed the same way. */
    @Test
    void anUnknownTokenIsAnsweredWithASignedNo() throws Exception {
        MvcResult result = introspect("a-token-nobody-minted",
                IntrospectionJwtResponseHandler.JWT_MEDIA_TYPE);

        Map<String, Object> introspection = JWTParser.parse(result.getResponse().getContentAsString())
                .getJWTClaimsSet().getJSONObjectClaim(IntrospectionJwtResponseHandler.TOKEN_INTROSPECTION);

        assertThat(introspection).containsEntry("active", false);
    }

    /**
     * The typ header doing its job: the decoder this server uses for access tokens will not take an
     * introspection response, which is exactly the confusion RFC 9701 gives it the type to prevent.
     */
    @Test
    void theServersOwnAccessTokenDecoderRefusesIt() throws Exception {
        String response = introspect(accessToken(), IntrospectionJwtResponseHandler.JWT_MEDIA_TYPE)
                .getResponse().getContentAsString();

        assertThatThrownBy(() -> jwtDecoder.decode(response))
                .hasMessageContaining("typ");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/introspection-jwt")).andExpect(status().isOk());
    }

    private MvcResult introspect(String token, String accept) throws Exception {
        return introspect(token, accept, properties.exchangeClient());
    }

    private MvcResult introspect(String token, String accept, DemoProperties.Client caller)
            throws Exception {
        return mockMvc().perform(post("/oauth2/introspect")
                        .header(HttpHeaders.AUTHORIZATION, basicAuth(caller))
                        .header(HttpHeaders.ACCEPT, accept)
                        .param("token", token))
                .andExpect(status().isOk())
                .andReturn();
    }

    @SuppressWarnings("unchecked")
    private String accessToken() throws Exception {
        MvcResult result = mockMvc().perform(post("/oauth2/token")
                        .header(HttpHeaders.AUTHORIZATION, basicAuth(properties.exchangeClient()))
                        .param("grant_type", "client_credentials")
                        .param("scope", "api.read"))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, Object> body = new tools.jackson.databind.ObjectMapper()
                .readValue(result.getResponse().getContentAsString(), Map.class);
        return String.valueOf(body.get("access_token"));
    }

    private static String basicAuth(DemoProperties.Client client) {
        String credentials = client.clientId() + ":" + client.clientSecret();
        return "Basic " + Base64.getEncoder()
                .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }
}
