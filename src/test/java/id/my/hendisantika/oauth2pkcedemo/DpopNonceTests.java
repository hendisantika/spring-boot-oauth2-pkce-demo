package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.DpopNonceController;
import id.my.hendisantika.oauth2pkcedemo.controller.NonceApiController;
import id.my.hendisantika.oauth2pkcedemo.security.DpopKeyPair;
import id.my.hendisantika.oauth2pkcedemo.security.DpopNonceRequiredFilter;
import id.my.hendisantika.oauth2pkcedemo.security.DpopNonceStore;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.nimbusds.jwt.JWTParser;

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
 * Date: 14/09/26
 * Time: 23.05
 */
@SpringBootTest
class DpopNonceTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private DpopNonceStore nonceStore;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** A proof can carry the value, which is the whole mechanism: the client cannot invent it. */
    @Test
    void aProofCanEchoANonce() throws Exception {
        DpopKeyPair key = DpopKeyPair.generate();
        String nonce = nonceStore.issue();

        String withNonce = key.proof("GET", "http://localhost:8080/nonce/me", null, nonce);
        String without = key.proof("GET", "http://localhost:8080/nonce/me", null);

        assertThat(JWTParser.parse(withNonce).getJWTClaimsSet().getClaim("nonce")).isEqualTo(nonce);
        assertThat(JWTParser.parse(without).getJWTClaimsSet().getClaim("nonce")).isNull();
    }

    /** Single use is this server's policy; the specification leaves the choice to whoever issues. */
    @Test
    void aNonceIsSpentTheFirstTimeItIsAccepted() {
        String nonce = nonceStore.issue();

        assertThat(nonceStore.knows(nonce)).isTrue();
        assertThat(nonceStore.spend(nonce)).isTrue();
        assertThat(nonceStore.spend(nonce)).isFalse();
        assertThat(nonceStore.spend("something-nobody-issued")).isFalse();
        assertThat(nonceStore.spend(null)).isFalse();
    }

    /** RFC 9449 section 9: the refusal names the error and supplies the nonce to use next. */
    @Test
    void aProofWithoutANonceIsChallenged() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new DpopNonceRequiredFilter(nonceStore).doFilter(
                requestWithProof(DpopKeyPair.generate().proof("GET", uri(), null)), response, chain);

        assertThat(chain.getRequest()).isNull();
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE))
                .startsWith("DPoP ")
                .contains(DpopNonceRequiredFilter.USE_DPOP_NONCE);
        assertThat(response.getHeader(DpopNonceRequiredFilter.NONCE_HEADER)).isNotBlank();
    }

    /** The nonce it just handed out is accepted, and a fresh one comes back with the answer. */
    @Test
    void theNonceFromTheChallengeIsAcceptedOnce() throws Exception {
        DpopNonceRequiredFilter filter = new DpopNonceRequiredFilter(nonceStore);
        DpopKeyPair key = DpopKeyPair.generate();
        MockHttpServletResponse challenge = new MockHttpServletResponse();
        filter.doFilter(requestWithProof(key.proof("GET", uri(), null)), challenge, new MockFilterChain());
        String nonce = challenge.getHeader(DpopNonceRequiredFilter.NONCE_HEADER);

        MockHttpServletResponse accepted = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(requestWithProof(key.proof("GET", uri(), null, nonce)), accepted, chain);

        assertThat(chain.getRequest()).isNotNull();
        assertThat(accepted.getHeader(DpopNonceRequiredFilter.NONCE_HEADER))
                .isNotBlank()
                .isNotEqualTo(nonce);

        // The same one a second time is refused, with another nonce to try.
        MockHttpServletResponse again = new MockHttpServletResponse();
        MockFilterChain second = new MockFilterChain();
        filter.doFilter(requestWithProof(key.proof("GET", uri(), null, nonce)), again, second);

        assertThat(second.getRequest()).isNull();
        assertThat(again.getStatus()).isEqualTo(401);
    }

    /**
     * A request with no proof at all is left alone: Spring answers that itself, and answering it
     * here would replace what it says with something less true.
     */
    @Test
    void aRequestWithNoProofIsNotThisFiltersBusiness() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", NonceApiController.NONCE_API_URI);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new DpopNonceRequiredFilter(nonceStore).doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull();
        assertThat(response.getHeader(DpopNonceRequiredFilter.NONCE_HEADER)).isNull();
    }

    /** The endpoint answers nothing to a caller with no token, as any resource server would. */
    @Test
    void theResourceStillNeedsAToken() throws Exception {
        MvcResult result = mockMvc().perform(get(NonceApiController.NONCE_API_URI)).andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void theProbeClientIsPublicAndUsesProofKey() {
        RegisteredClient client =
                registeredClientRepository.findByClientId(properties.dpopNonceClient().clientId());

        assertThat(client).isNotNull();
        assertThat(client.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(client.getAuthorizationGrantTypes()).containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getRedirectUris())
                .containsExactly(properties.issuerUri() + DpopNonceController.CALLBACK_URI);
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/dpop-nonce")).andExpect(status().isOk());
    }

    private String uri() {
        return properties.issuerUri() + NonceApiController.NONCE_API_URI;
    }

    private static MockHttpServletRequest requestWithProof(String proof) {
        MockHttpServletRequest request =
                new MockHttpServletRequest("GET", NonceApiController.NONCE_API_URI);
        request.addHeader(DpopNonceRequiredFilter.DPOP_HEADER, proof);
        return request;
    }
}
