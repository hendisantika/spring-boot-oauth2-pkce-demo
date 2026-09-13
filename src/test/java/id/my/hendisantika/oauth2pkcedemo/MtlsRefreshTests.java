package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.DeviceClientAuthenticationConverter;
import id.my.hendisantika.oauth2pkcedemo.security.MtlsMaterial;
import id.my.hendisantika.oauth2pkcedemo.service.MtlsRefreshService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.security.cert.X509Certificate;

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
 * Date: 14/09/26
 * Time: 10.22
 */
@SpringBootTest
class MtlsRefreshTests extends AbstractMySqlIntegrationTest {

    private static final String X509_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private MtlsRefreshService mtlsRefreshService;

    @Autowired
    private MtlsMaterial material;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /**
     * The client credentials grant issues no refresh token, so the client on the mTLS page cannot
     * answer this question at all. This one holds the device grant, which does - and authenticates
     * with its certificate, having no secret to authenticate with instead.
     */
    @Test
    void theClientHasACertificateAndAGrantThatIssuesRefreshTokens() {
        RegisteredClient client =
                registeredClientRepository.findByClientId(mtlsRefreshService.clientId());

        assertThat(client).isNotNull();
        assertThat(client.getClientSecret()).isNull();
        assertThat(client.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);
        assertThat(client.getAuthorizationGrantTypes())
                .containsExactlyInAnyOrder(AuthorizationGrantType.DEVICE_CODE,
                        AuthorizationGrantType.REFRESH_TOKEN);
        assertThat(client.getTokenSettings().isX509CertificateBoundAccessTokens()).isTrue();
        // Rotated on every use, so a refresh token seen once is worthless the second time.
        assertThat(client.getTokenSettings().isReuseRefreshTokens()).isFalse();
    }

    /**
     * The refusal the page shows for a request carrying no certificate. It is
     * {@code invalid_client}, not a complaint about the refresh token: the caller never
     * authenticated, so the token was never looked at.
     */
    @Test
    void refreshingWithoutACertificateIsRefusedAsAClient() throws Exception {
        MvcResult result = mockMvc().perform(post("/oauth2/token")
                        .param("grant_type", AuthorizationGrantType.REFRESH_TOKEN.getValue())
                        .param("refresh_token", "a-refresh-token-that-does-not-exist")
                        .param("client_id", mtlsRefreshService.clientId()))
                .andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(401);
        assertThat(result.getResponse().getContentAsString()).contains("invalid_client");
    }

    /**
     * The converter that lets a credential-less device client be served has to stand aside for a
     * client holding a certificate - otherwise this one is authenticated as public and then refused
     * for not being registered that way, which is invalid_client for entirely the wrong reason.
     */
    @Test
    void theDeviceConverterLeavesACertificateHoldingClientAlone() {
        DeviceClientAuthenticationConverter converter =
                new DeviceClientAuthenticationConverter("/oauth2/device_authorization", "/oauth2/token");

        assertThat(converter.convert(deviceRequest(false))).isNotNull();
        assertThat(converter.convert(deviceRequest(true))).isNull();
    }

    /** The public device client still is served, which is what that converter exists for. */
    @Test
    void thePublicDeviceClientIsStillConverted() {
        DeviceClientAuthenticationConverter converter =
                new DeviceClientAuthenticationConverter("/oauth2/device_authorization", "/oauth2/token");
        MockHttpServletRequest request = deviceRequest(false);
        request.setParameter("client_id", properties.client().clientId());

        Authentication authentication = converter.convert(request);

        assertThat(authentication).isNotNull();
        assertThat(authentication.getPrincipal()).isEqualTo(properties.client().clientId());
    }

    /**
     * A refusal has to come from the authorization server to mean anything, so the stranger's
     * certificate is in the trust store: the handshake succeeds and the request arrives.
     */
    @Test
    void theStrangerCertificateIsADifferentOneTheTransportTrusts() {
        assertThat(material.strangerCertificateThumbprint())
                .isNotBlank()
                .isNotEqualTo(material.clientCertificateThumbprint());
        assertThat(material.getStrangerKeyStorePath()).exists();
        assertThat(mtlsRefreshService.strangerThumbprint())
                .isEqualTo(material.strangerCertificateThumbprint());
    }

    /** The two endpoints the page contrasts: the TLS listener, and the one everything else uses. */
    @Test
    void theTwoEndpointsAreTheTlsOneAndTheOrdinaryOne() {
        assertThat(mtlsRefreshService.mtlsTokenEndpoint()).startsWith("https://localhost:8443/");
        assertThat(mtlsRefreshService.plainTokenEndpoint())
                .isEqualTo(properties.issuerUri() + "/oauth2/token");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/mtls-refresh")).andExpect(status().isOk());
        // Nothing pending, so the run redirects back rather than failing.
        mockMvc().perform(post("/mtls-refresh/run").with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    private MockHttpServletRequest deviceRequest(boolean withCertificate) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/device_authorization");
        request.setParameter("client_id", mtlsRefreshService.clientId());
        if (withCertificate) {
            request.setAttribute(X509_ATTRIBUTE, new X509Certificate[]{material.getClientCertificate()});
        }
        return request;
    }
}
