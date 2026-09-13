package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.LogoutDemoController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

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
 * Time: 13.21
 */
@SpringBootTest
class RefreshAndLogoutFlowTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    @Test
    void confidentialClientKeepsASecretAndStillRequiresProofKey() {
        RegisteredClient client =
                registeredClientRepository.findByClientId(properties.confidentialClient().clientId());

        assertThat(client).isNotNull();
        assertThat(client.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(client.getClientSecret()).isNotNull();
        // Stored hashed, and PKCE is required even though the client can authenticate itself.
        assertThat(client.getClientSecret()).isNotEqualTo(properties.confidentialClient().clientSecret());
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
    }

    @Test
    void bothClientsAllowTheRefreshTokenGrant() {
        for (DemoProperties.Client configured : java.util.List.of(properties.client(),
                properties.confidentialClient())) {
            RegisteredClient client = registeredClientRepository.findByClientId(configured.clientId());
            assertThat(client).as("client %s", configured.clientId()).isNotNull();
            assertThat(client.getAuthorizationGrantTypes())
                    .as("grant types of %s", configured.clientId())
                    .contains(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN);
            // Rotation is what makes a stolen refresh token detectable.
            assertThat(client.getTokenSettings().isReuseRefreshTokens()).isFalse();
        }
    }

    @Test
    void onlyTheConfidentialRegistrationCarriesASecret() {
        ClientRegistration publicClient =
                clientRegistrationRepository.findByRegistrationId(properties.client().registrationId());
        ClientRegistration confidential =
                clientRegistrationRepository.findByRegistrationId(properties.confidentialClient().registrationId());

        assertThat(publicClient.getClientAuthenticationMethod()).isEqualTo(ClientAuthenticationMethod.NONE);
        assertThat(publicClient.getClientSecret()).isNullOrEmpty();
        assertThat(confidential.getClientAuthenticationMethod())
                .isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(confidential.getClientSecret()).isNotEmpty();

        // Both are pinned to PKCE; Spring only applies it automatically to public clients.
        assertThat(publicClient.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(confidential.getClientSettings().isRequireProofKey()).isTrue();
    }

    @Test
    void everyRegistrationAdvertisesTheEndSessionEndpointUsedByRpInitiatedLogout() {
        for (DemoProperties.Client configured : java.util.List.of(properties.client(),
                properties.confidentialClient())) {
            ClientRegistration registration =
                    clientRegistrationRepository.findByRegistrationId(configured.registrationId());
            assertThat(registration.getProviderDetails().getConfigurationMetadata())
                    .as("provider metadata of %s", configured.registrationId())
                    .containsEntry(LogoutDemoController.END_SESSION_ENDPOINT,
                            properties.issuerUri() + "/connect/logout");
        }
    }

    @Test
    void refreshAndLogoutPagesRequireAnAuthenticatedSession() throws Exception {
        String expected = "/oauth2/authorization/" + properties.client().registrationId();

        for (String path : java.util.List.of("/refresh", "/logout-demo")) {
            MvcResult result = mockMvc().perform(get(path))
                    .andExpect(status().is3xxRedirection())
                    .andReturn();
            assertThat(result.getResponse().getRedirectedUrl()).as("redirect for %s", path).endsWith(expected);
        }
    }
}
