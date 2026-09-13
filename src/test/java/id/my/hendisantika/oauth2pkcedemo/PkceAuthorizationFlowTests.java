package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

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
 * Time: 13.20
 */
@SpringBootTest
class PkceAuthorizationFlowTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_VERIFIER =
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-vErsWXBGJiGMvZmJXzxg";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    @Test
    void flywaySeedsTheDemoUsersIntoMySql() {
        for (DemoProperties.DemoUser demoUser : properties.demoUsers()) {
            assertThat(userRepository.findByUsername(demoUser.username()))
                    .as("demo user %s", demoUser.username())
                    .isPresent()
                    .hasValueSatisfying(user -> {
                        assertThat(user.isEnabled()).isTrue();
                        // Stored hashed, never in clear text.
                        assertThat(user.getPassword()).isNotEqualTo(demoUser.password());
                        assertThat(user.getAuthorities()).containsExactlyInAnyOrderElementsOf(demoUser.authorities());
                    });
        }
    }

    @Test
    void registeredClientIsAPublicClientThatRequiresProofKey() {
        RegisteredClient client = registeredClientRepository.findByClientId(properties.client().clientId());

        assertThat(client).isNotNull();
        assertThat(client.getClientSecret()).isNull();
        assertThat(client.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
    }

    @Test
    void authorizationRequestWithoutCodeChallengeIsRejected() throws Exception {
        MvcResult result = mockMvc().perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", properties.client().clientId())
                        .queryParam("scope", "openid")
                        .queryParam("state", "state-without-pkce")
                        .queryParam("redirect_uri", redirectUri()))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        // RFC 7636 section 4.4.1: a client registered with require-proof-key may not skip PKCE.
        assertThat(result.getResponse().getRedirectedUrl())
                .contains("error=invalid_request")
                .contains("code_challenge");
    }

    @Test
    void authorizationRequestWithCodeChallengeReachesTheLoginPage() throws Exception {
        MvcResult result = mockMvc().perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", properties.client().clientId())
                        .queryParam("scope", "openid profile email")
                        .queryParam("state", "state-with-pkce")
                        .queryParam("redirect_uri", redirectUri())
                        .queryParam("code_challenge", codeChallenge())
                        .queryParam("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        // A valid request is not rejected; it is parked until the user signs in.
        assertThat(result.getResponse().getRedirectedUrl()).endsWith("/login");
    }

    @Test
    void startingAtTheClientProducesAnS256Challenge() throws Exception {
        MvcResult result = mockMvc()
                .perform(get("/oauth2/authorization/" + properties.client().registrationId()))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl())
                .contains("code_challenge=")
                .contains("code_challenge_method=S256")
                .doesNotContain("client_secret");
    }

    private String redirectUri() {
        return properties.issuerUri() + "/login/oauth2/code/" + properties.client().registrationId();
    }

    private static String codeChallenge() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(CODE_VERIFIER.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
