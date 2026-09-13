package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.service.DeviceFlowService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
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
 * Time: 13.40
 */
@SpringBootTest
class DeviceAuthorizationFlowTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private DeviceFlowService deviceFlowService;

    @Autowired
    private AuthorizationServerSettings authorizationServerSettings;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    @Test
    void onlyThePublicClientIsRegisteredForTheDeviceGrant() {
        RegisteredClient publicClient =
                registeredClientRepository.findByClientId(properties.client().clientId());
        RegisteredClient confidential =
                registeredClientRepository.findByClientId(properties.confidentialClient().clientId());

        assertThat(publicClient.getAuthorizationGrantTypes()).contains(AuthorizationGrantType.DEVICE_CODE);
        // The device grant exists for input-constrained public clients; the confidential one has a
        // browser and should use the authorization code flow.
        assertThat(confidential.getAuthorizationGrantTypes()).doesNotContain(AuthorizationGrantType.DEVICE_CODE);
    }

    @Test
    void deviceScopesExcludeOpenid() {
        // Spring Authorization Server answers invalid_scope for openid on this grant, because
        // OpenID Connect is not defined over the device flow - so there is never an ID token here.
        assertThat(properties.client().scopes()).contains(OidcScopes.OPENID);
        assertThat(deviceFlowService.deviceScopes())
                .doesNotContain(OidcScopes.OPENID)
                .contains(OidcScopes.PROFILE)
                .contains(OidcScopes.EMAIL);
    }

    @Test
    void publicClientReachesTheDeviceAuthorizationEndpointWithNothingButItsClientId() throws Exception {
        // Without DeviceClientAuthenticationConverter this is bounced to /login, because nothing in
        // Spring Authorization Server authenticates a public client at this endpoint.
        mockMvc().perform(post(authorizationServerSettings.getDeviceAuthorizationEndpoint())
                        .param("client_id", properties.client().clientId())
                        .param("scope", deviceFlowService.deviceScopes()))
                .andExpect(status().isOk());
    }

    @Test
    void deviceAuthorizationRequestIsRejectedForAnUnknownClient() throws Exception {
        mockMvc().perform(post(authorizationServerSettings.getDeviceAuthorizationEndpoint())
                        .param("client_id", "no-such-client")
                        .param("scope", deviceFlowService.deviceScopes()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void openidIsRejectedOnTheDeviceGrant() throws Exception {
        MvcResult result = mockMvc().perform(post(authorizationServerSettings.getDeviceAuthorizationEndpoint())
                        .param("client_id", properties.client().clientId())
                        .param("scope", OidcScopes.OPENID))
                .andExpect(status().isBadRequest())
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).contains("invalid_scope");
    }

    @Test
    void theDevicePagesAreReachableWithoutSigningIn() throws Exception {
        // A television has no session. Both pages must render for an anonymous visitor.
        for (String path : java.util.List.of("/device", "/activate")) {
            mockMvc().perform(get(path)).andExpect(status().isOk());
        }
    }
}
