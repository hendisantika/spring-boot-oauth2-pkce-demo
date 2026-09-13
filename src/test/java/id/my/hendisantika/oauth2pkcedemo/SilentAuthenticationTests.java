package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.SilentAuthController;
import id.my.hendisantika.oauth2pkcedemo.security.AuthenticationFreshness;
import id.my.hendisantika.oauth2pkcedemo.security.MaxAgeRequiredFilter;
import id.my.hendisantika.oauth2pkcedemo.security.PromptNoneFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

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
 * Time: 17.20
 */
@SpringBootTest
class SilentAuthenticationTests extends AbstractMySqlIntegrationTest {

    private static final String AUTHORIZE = "/oauth2/authorize";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    private PromptNoneFilter filter() {
        return new PromptNoneFilter(AUTHORIZE, registeredClientRepository, properties.issuerUri());
    }

    /**
     * The case Spring Authorization Server implements and never reaches: with its endpoints behind
     * an authentication entry point, an unauthenticated request is redirected to the login page -
     * the one thing prompt=none forbids.
     */
    @Test
    void anUnauthenticatedSilentRequestIsRefusedAtTheRedirectUri() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter().doFilter(silentRequest(null), response, chain);

        assertThat(chain.getRequest()).isNull();
        assertThat(response.getRedirectedUrl())
                .startsWith(properties.issuerUri() + SilentAuthController.CALLBACK_URI)
                .contains("error=" + PromptNoneFilter.LOGIN_REQUIRED)
                .contains("state=a-state");
    }

    /** A session that is there and fresh enough is nobody's business but the server's. */
    @Test
    void anOrdinarySilentRequestIsLeftToTheAuthorizationServer() throws Exception {
        MockFilterChain chain = new MockFilterChain();

        filter().doFilter(silentRequest(authenticated(Instant.now())), new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isNotNull();
    }

    /**
     * Two rules of this demo colliding: max_age says the session must be new, prompt=none says the
     * user may not be asked. Both cannot hold, and the answer is an error the client can read.
     */
    @Test
    void aSilentRequestThatCannotMeetMaxAgeIsRefusedRatherThanPrompted() throws Exception {
        MockHttpServletRequest request = silentRequest(authenticated(Instant.now().minus(1, ChronoUnit.HOURS)));
        request.setParameter(AuthenticationFreshness.MAX_AGE, "0");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter().doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNull();
        assertThat(response.getRedirectedUrl()).contains("error=" + PromptNoneFilter.LOGIN_REQUIRED);
    }

    /** And the filter that would otherwise send them to the login page stands down. */
    @Test
    void theMaxAgeFilterDoesNotPromptWhenItMayNotPrompt() throws Exception {
        MockHttpServletRequest request = silentRequest(authenticated(Instant.now().minus(1, ChronoUnit.HOURS)));
        request.setParameter(AuthenticationFreshness.MAX_AGE, "0");
        request.setQueryString("state=a-state&max_age=0&prompt=none");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new MaxAgeRequiredFilter(AUTHORIZE).doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull();
        assertThat(response.getRedirectedUrl()).isNull();
    }

    /** none with anything else is malformed, and the authorization server says so itself. */
    @Test
    void noneCombinedWithAnotherPromptIsLeftToTheServer() throws Exception {
        MockHttpServletRequest request = silentRequest(null);
        request.setParameter(PromptNoneFilter.PROMPT, "none login");
        MockFilterChain chain = new MockFilterChain();

        filter().doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isNotNull();
    }

    /**
     * An error response goes to a registered redirect URI or nowhere. Echoing the parameter back
     * would make every refusal an open redirect.
     */
    @Test
    void anUnregisteredRedirectUriIsNotWrittenTo() throws Exception {
        MockHttpServletRequest request = silentRequest(null);
        request.setParameter("redirect_uri", "https://somewhere-else.example/callback");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter().doFilter(request, response, chain);

        assertThat(response.getRedirectedUrl()).isNull();
        assertThat(chain.getRequest()).isNotNull();
    }

    /** Consent stays on for this client, or the middle question would answer itself. */
    @Test
    void theProbeClientAsksForConsent() {
        RegisteredClient client =
                registeredClientRepository.findByClientId(properties.silentClient().clientId());

        assertThat(client).isNotNull();
        assertThat(client.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(client.getAuthorizationGrantTypes()).containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(client.getClientSettings().isRequireAuthorizationConsent()).isTrue();
        assertThat(client.getRedirectUris())
                .containsExactly(properties.issuerUri() + SilentAuthController.CALLBACK_URI);
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/silent-auth")).andExpect(status().isOk());
    }

    private MockHttpServletRequest silentRequest(Authentication authentication) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", AUTHORIZE);
        request.setParameter("client_id", properties.silentClient().clientId());
        request.setParameter("redirect_uri", properties.issuerUri() + SilentAuthController.CALLBACK_URI);
        request.setParameter("state", "a-state");
        request.setParameter(PromptNoneFilter.PROMPT, PromptNoneFilter.NONE);
        SecurityContextHolder.getContext().setAuthentication(authentication == null
                ? new AnonymousAuthenticationToken("key", "anonymous",
                        AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"))
                : authentication);
        return request;
    }

    private static Authentication authenticated(Instant authenticatedAt) {
        return UsernamePasswordAuthenticationToken.authenticated("hendi", null, List.of(
                FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
                        .issuedAt(authenticatedAt).build()));
    }
}
