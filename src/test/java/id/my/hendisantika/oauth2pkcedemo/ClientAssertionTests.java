package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.ClientAssertionKey;
import id.my.hendisantika.oauth2pkcedemo.service.ClientAssertionService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Duration;

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
 * Time: 14.42
 */
@SpringBootTest
class ClientAssertionTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private ClientAssertionKey clientAssertionKey;

    @Autowired
    private AuthorizationServerSettings settings;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    @Test
    void theAssertionClientHasNoSecretAtAll() {
        RegisteredClient client =
                registeredClientRepository.findByClientId(properties.assertionClient().clientId());

        assertThat(client).isNotNull();
        assertThat(client.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        // Nothing confidential is stored server-side; only a pointer to the client's public keys.
        assertThat(client.getClientSecret()).isNull();
        assertThat(client.getClientSettings().getJwkSetUrl())
                .isEqualTo(properties.issuerUri() + "/client-jwks.json");
        assertThat(client.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm())
                .isEqualTo(SignatureAlgorithm.RS256);
        // No user is involved in this exchange.
        assertThat(client.getAuthorizationGrantTypes())
                .containsExactly(AuthorizationGrantType.CLIENT_CREDENTIALS);
    }

    @Test
    void theClientPublishesOnlyItsPublicKey() throws Exception {
        MvcResult result = mockMvc().perform(get("/client-jwks.json"))
                .andExpect(status().isOk())
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertThat(body).contains("\"kty\":\"RSA\"").contains("\"n\":").contains("\"e\":");
        // The private parameters must never appear here.
        assertThat(body).doesNotContain("\"d\":").doesNotContain("\"p\":").doesNotContain("\"q\":");
    }

    @Test
    void anAssertionNamesTheClientAndTheEndpointItIsFor() throws Exception {
        String clientId = properties.assertionClient().clientId();
        String audience = properties.issuerUri() + settings.getTokenEndpoint();

        var claims = JWTParser.parse(clientAssertionKey.assertion(clientId, audience, Duration.ofMinutes(2)))
                .getJWTClaimsSet();

        // iss and sub are both the client: it asserts its own identity, not a user's.
        assertThat(claims.getIssuer()).isEqualTo(clientId);
        assertThat(claims.getSubject()).isEqualTo(clientId);
        // aud pins it to one endpoint, so it cannot be replayed at another.
        assertThat(claims.getAudience()).containsExactly(audience);
        assertThat(claims.getJWTID()).isNotBlank();
        assertThat(claims.getExpirationTime()).isNotNull();
    }

    @Test
    void anAssertionSignedByAnotherKeyIsRejected() throws Exception {
        String clientId = properties.assertionClient().clientId();
        String audience = properties.issuerUri() + settings.getTokenEndpoint();

        MvcResult result = mockMvc().perform(post(settings.getTokenEndpoint())
                        .param("grant_type", "client_credentials")
                        .param("scope", String.join(" ", properties.assertionClient().scopes()))
                        .param("client_id", clientId)
                        .param("client_assertion_type", ClientAssertionService.JWT_BEARER_ASSERTION_TYPE)
                        .param("client_assertion",
                                clientAssertionKey.assertionSignedByAnotherKey(
                                        clientId, audience, Duration.ofMinutes(2))))
                .andExpect(status().isUnauthorized())
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).contains("invalid_client");
    }

    @Test
    void anExpiredAssertionIsRejected() throws Exception {
        String clientId = properties.assertionClient().clientId();
        String audience = properties.issuerUri() + settings.getTokenEndpoint();

        mockMvc().perform(post(settings.getTokenEndpoint())
                        .param("grant_type", "client_credentials")
                        .param("scope", String.join(" ", properties.assertionClient().scopes()))
                        .param("client_id", clientId)
                        .param("client_assertion_type", ClientAssertionService.JWT_BEARER_ASSERTION_TYPE)
                        .param("client_assertion",
                                clientAssertionKey.assertion(clientId, audience, Duration.ofMinutes(-2))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void theAssertionPageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/assertion")).andExpect(status().isOk());
    }
}
