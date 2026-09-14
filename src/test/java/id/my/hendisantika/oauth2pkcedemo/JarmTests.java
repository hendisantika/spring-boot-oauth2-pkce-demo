package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.JarmController;
import id.my.hendisantika.oauth2pkcedemo.security.JarmResponseFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
 * Date: 15/09/26
 * Time: 11.30
 */
@SpringBootTest
class JarmTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** Without the mode, the answer is what it has always been: loose parameters. */
    @Test
    void anOrdinaryResponseCarriesItsParametersInTheClear() throws Exception {
        String location = authorize("query", "openid profile");

        assertThat(location).contains("code=").doesNotContain("response=");
    }

    /** The whole response in one signed JWT, with the three claims the loose form has no room for. */
    @Test
    void aJwtResponseIsSignedAndAddressedToTheClient() throws Exception {
        String location = authorize("jwt", "openid profile");
        String response = parameterOf(location, JarmResponseFilter.RESPONSE);

        assertThat(location).doesNotContain("code=");
        assertThat(response).isNotNull();

        var jwt = jwtDecoder.decode(response);
        assertThat(jwt.getClaimAsString("iss")).isEqualTo(properties.issuerUri());
        assertThat(jwt.getAudience()).containsExactly(properties.jarmClient().clientId());
        assertThat(jwt.getExpiresAt()).isAfter(Instant.now());
        assertThat(jwt.getClaimAsString("code")).isNotBlank();
        assertThat(jwt.getClaimAsString("state")).isNotBlank();
    }

    /** query.jwt means the same thing, and the code flow needs no other delivery. */
    @Test
    void queryJwtIsTheSameMode() throws Exception {
        String response = parameterOf(authorize("query.jwt", "openid profile"),
                JarmResponseFilter.RESPONSE);

        assertThat(jwtDecoder.decode(response).getClaimAsString("code")).isNotBlank();
    }

    /**
     * A client that cannot trust an error is no better off than one that cannot trust a code, so a
     * refusal is carried exactly the same way.
     */
    @Test
    void aRefusalIsSignedTheSameWay() throws Exception {
        String response = parameterOf(authorize("jwt", "openid admin.everything"),
                JarmResponseFilter.RESPONSE);

        var jwt = jwtDecoder.decode(response);
        assertThat(jwt.getClaimAsString("error")).isEqualTo("invalid_scope");
        assertThat(jwt.getClaimAsString("code")).isNull();
    }

    /** The signature is over the bytes that were there, so a rewritten claim is refused. */
    @Test
    void aRewrittenClaimNoLongerVerifies() throws Exception {
        String response = parameterOf(authorize("jwt", "openid profile"),
                JarmResponseFilter.RESPONSE);
        String[] parts = response.split("\\.");
        String forged = parts[0] + "."
                + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                        "{\"code\":\"a-code-of-my-own-choosing\"}".getBytes(StandardCharsets.UTF_8))
                + "." + parts[2];

        assertThatThrownBy(() -> jwtDecoder.decode(forged)).isInstanceOf(Exception.class);
    }

    /** Only the modes this implements are acted on; anything else is left to the server. */
    @Test
    void onlyTheQueryJwtModesAreRecognised() {
        assertThat(JarmResponseFilter.QUERY_JWT_MODES).containsExactlyInAnyOrder("jwt", "query.jwt");
        assertThat(JarmResponseFilter.wantsJwtResponse(requestWithMode("jwt"))).isTrue();
        assertThat(JarmResponseFilter.wantsJwtResponse(requestWithMode("query.jwt"))).isTrue();
        assertThat(JarmResponseFilter.wantsJwtResponse(requestWithMode("form_post"))).isFalse();
        assertThat(JarmResponseFilter.wantsJwtResponse(requestWithMode(null))).isFalse();
    }

    /** A mode nothing here implements is ignored entirely, which is the point of the last row. */
    @Test
    void anUnimplementedModeIsAnsweredInTheClear() throws Exception {
        String location = authorize("form_post", "openid profile");

        assertThat(location).contains("code=").doesNotContain("response=");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jarm")).andExpect(status().isOk());
    }

    private String authorize(String responseMode, String scope) throws Exception {
        MvcResult result = mockMvc().perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", properties.jarmClient().clientId())
                        .queryParam("scope", scope)
                        .queryParam("redirect_uri", properties.issuerUri() + JarmController.CALLBACK_URI)
                        .queryParam("state", "a-state")
                        .queryParam("code_challenge", CODE_CHALLENGE)
                        .queryParam("code_challenge_method", "S256")
                        .queryParam(JarmResponseFilter.RESPONSE_MODE, responseMode)
                        .with(user("hendi")))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        return result.getResponse().getRedirectedUrl();
    }

    private static MockHttpServletRequest requestWithMode(String mode) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        if (mode != null) {
            request.setParameter(JarmResponseFilter.RESPONSE_MODE, mode);
        }
        return request;
    }

    private static String parameterOf(String uri, String name) {
        Matcher matcher = Pattern.compile("[?&]" + name + "=([^&]*)").matcher(uri);
        return matcher.find() ? URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8) : null;
    }
}
