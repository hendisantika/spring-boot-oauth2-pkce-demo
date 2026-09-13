package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.DpopKeyPair;
import id.my.hendisantika.oauth2pkcedemo.service.RefreshTokenBindingService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
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
 * Date: 13/09/26
 * Time: 21.06
 */
@SpringBootTest
class RefreshTokenBindingTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RefreshTokenBindingService refreshTokenBindingService;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /**
     * The device grant is the only one here that gives a refresh token to a client holding no
     * credentials, which is the only case RFC 9449 section 5 has anything to say about.
     */
    @Test
    void onlyTheDeviceGrantGivesThisClientARefreshTokenToBind() {
        RegisteredClient client = registeredClientRepository.findByClientId(
                refreshTokenBindingService.clientId());

        assertThat(client).isNotNull();
        assertThat(client.getClientSecret()).isNull();
        assertThat(client.getAuthorizationGrantTypes())
                .contains(AuthorizationGrantType.DEVICE_CODE, AuthorizationGrantType.REFRESH_TOKEN);
    }

    /**
     * A public client could be issued a refresh token by the device grant and then had no way to
     * spend it: nothing in Spring Authorization Server authenticates a public client on a refresh
     * request, so it was answered with a redirect to the login page rather than JSON.
     */
    @Test
    void aPublicClientReachesTheTokenEndpointToRefresh() throws Exception {
        MvcResult result = mockMvc().perform(post("/oauth2/token")
                        .param("grant_type", AuthorizationGrantType.REFRESH_TOKEN.getValue())
                        .param("refresh_token", "a-refresh-token-that-does-not-exist")
                        .param("client_id", refreshTokenBindingService.clientId()))
                .andReturn();

        // Refused because the token is unknown, which is the point: it was refused by the token
        // endpoint rather than bounced to a login form.
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(result.getResponse().getContentAsString()).contains("invalid_grant");
    }

    /** A device holds its key before it asks for anything, or the tokens cannot be tied to it. */
    @Test
    void theKeyExistsBeforeTheCodesAreAskedFor() {
        DpopKeyPair key = DpopKeyPair.generate();

        assertThat(key.thumbprint()).isNotBlank();
        assertThat(key.publicJwkJson()).contains("\"kty\"").doesNotContain("\"d\"");
        // RFC 9449 section 4.2: a proof is for one method and one URL.
        assertThat(key.proof("POST", refreshTokenBindingService.tokenEndpoint(), null))
                .isNotEqualTo(key.proof("POST", refreshTokenBindingService.tokenEndpoint(), null));
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/refresh-binding")).andExpect(status().isOk());
        // Nothing to redeem yet, so the run is a no-op rather than an error.
        mockMvc().perform(post("/refresh-binding/run").with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    void theTokenEndpointIsTheOneTheProofsAreBoundTo() {
        assertThat(refreshTokenBindingService.tokenEndpoint())
                .isEqualTo(properties.issuerUri() + "/oauth2/token");
    }
}
