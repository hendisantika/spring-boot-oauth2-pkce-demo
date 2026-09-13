package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.jwk.JWKSet;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.MtlsMaterial;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.security.MessageDigest;
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
 * Time: 15.02
 */
@SpringBootTest
class MtlsTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private MtlsMaterial mtlsMaterial;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    @Test
    void theClientAuthenticatesWithACertificateAndGetsBoundTokens() {
        RegisteredClient client =
                registeredClientRepository.findByClientId(properties.mtlsClient().clientId());

        assertThat(client).isNotNull();
        assertThat(client.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);
        // Nothing in the request is a credential, so there is no secret to store.
        assertThat(client.getClientSecret()).isNull();
        // RFC 8705 section 3: this is what puts cnf.x5t#S256 into the issued token.
        assertThat(client.getTokenSettings().isX509CertificateBoundAccessTokens()).isTrue();
        assertThat(client.getAuthorizationGrantTypes())
                .containsExactly(AuthorizationGrantType.CLIENT_CREDENTIALS);
    }

    @Test
    void theClientCertificateIsSelfSigned() {
        // self_signed_tls_client_auth requires issuer and subject to match; a CA-issued certificate
        // would need tls_client_auth and a trust anchor instead.
        assertThat(mtlsMaterial.getClientCertificate().getIssuerX500Principal())
                .isEqualTo(mtlsMaterial.getClientCertificate().getSubjectX500Principal());
    }

    @Test
    void theThumbprintIsTheSha256OfTheEncodedCertificate() throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(mtlsMaterial.getClientCertificate().getEncoded());

        assertThat(mtlsMaterial.clientCertificateThumbprint())
                .isEqualTo(Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
    }

    @Test
    void thePublishedJwkSetCarriesTheCertificateChain() throws Exception {
        MvcResult result = mockMvc().perform(get("/mtls-jwks.json"))
                .andExpect(status().isOk())
                .andReturn();

        JWKSet jwkSet = JWKSet.parse(result.getResponse().getContentAsString());
        assertThat(jwkSet.getKeys()).hasSize(1);
        // Without x5c the authorization server has nothing to match the presented certificate
        // against, and self-signed client authentication cannot work.
        assertThat(jwkSet.getKeys().get(0).getParsedX509CertChain())
                .containsExactly(mtlsMaterial.getClientCertificate());
    }

    @Test
    void theMtlsPageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/mtls")).andExpect(status().isOk());
    }
}
