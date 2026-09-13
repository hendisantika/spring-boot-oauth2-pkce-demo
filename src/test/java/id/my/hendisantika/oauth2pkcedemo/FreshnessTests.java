package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.AuthenticationFreshness;
import id.my.hendisantika.oauth2pkcedemo.security.MaxAgeRequiredFilter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
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
 * Time: 15.10
 */
@SpringBootTest
class FreshnessTests extends AbstractMySqlIntegrationTest {

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

    /**
     * OpenID Connect Core section 3.1.2.1, including the case everyone relies on: {@code max_age=0}
     * asks for a new authentication now. Rounded to whole seconds an authentication made moments ago
     * has an elapsed time of zero, which is not greater than zero, and the parameter would never do
     * anything at all.
     */
    @Test
    void zeroGraceIsNotSatisfiedByAnAuthenticationFromAMomentAgo() {
        Instant now = Instant.now();

        assertThat(AuthenticationFreshness.satisfies(now, 0L)).isFalse();
        assertThat(AuthenticationFreshness.satisfies(now, 60L)).isTrue();
        assertThat(AuthenticationFreshness.satisfies(now.minus(2, ChronoUnit.MINUTES), 60L)).isFalse();
        assertThat(AuthenticationFreshness.satisfies(now.minus(2, ChronoUnit.MINUTES), 3600L)).isTrue();
        // No max_age is no question, so nothing to fail.
        assertThat(AuthenticationFreshness.satisfies((Instant) null, null)).isTrue();
    }

    @Test
    void onlyANumberOfSecondsIsAMaxAge() {
        assertThat(AuthenticationFreshness.parse("300")).isEqualTo(300L);
        assertThat(AuthenticationFreshness.parse("0")).isEqualTo(0L);
        assertThat(AuthenticationFreshness.parse("-1")).isNull();
        assertThat(AuthenticationFreshness.parse("soon")).isNull();
    }

    /** auth_time is the latest factor, the way Spring Authorization Server computes it. */
    @Test
    void theAuthenticationTimeIsTheMostRecentFactor() {
        Instant password = Instant.now().minus(10, ChronoUnit.MINUTES);
        Instant secondFactor = Instant.now().minus(1, ChronoUnit.MINUTES);
        Authentication authentication = authenticatedWith(password, secondFactor);

        assertThat(AuthenticationFreshness.authenticatedAt(authentication)).isEqualTo(secondFactor);
        assertThat(AuthenticationFreshness.factors(authentication)).hasSize(2);
    }

    /** A stale session is sent round again, with its authentication taken away but its session kept. */
    @Test
    void aStaleAuthorizationRequestIsSentBackForANewLogin() throws Exception {
        MockHttpServletRequest request = authorizationRequest("0");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new MaxAgeRequiredFilter(AUTHORIZE).doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl()).startsWith(AUTHORIZE).contains("max_age=0");
        assertThat(chain.getRequest()).isNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        // The session lives on: the client's own authorization request is in there, and losing it
        // would strand the callback.
        assertThat(request.getSession(false)).isNotNull();
    }

    /** The request coming back from that login is let through, or it would bounce for ever. */
    @Test
    void theSameRequestIsNotSentBackTwice() throws Exception {
        MaxAgeRequiredFilter filter = new MaxAgeRequiredFilter(AUTHORIZE);
        MockHttpServletRequest first = authorizationRequest("0");
        filter.doFilter(first, new MockHttpServletResponse(), new MockFilterChain());

        MockHttpServletRequest resumed = authorizationRequest("0");
        resumed.setSession(first.getSession(false));
        SecurityContextHolder.getContext().setAuthentication(authenticatedWith(Instant.now()));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(resumed, response, chain);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    void aFreshEnoughRequestIsLeftAlone() throws Exception {
        for (String maxAge : List.of("3600", "", "not-a-number")) {
            MockHttpServletRequest request = authorizationRequest(maxAge);
            MockFilterChain chain = new MockFilterChain();

            new MaxAgeRequiredFilter(AUTHORIZE).doFilter(request, new MockHttpServletResponse(), chain);

            assertThat(chain.getRequest()).as("max_age=%s", maxAge).isNotNull();
        }
    }

    /** The probe needs its own registration, or a consent screen would sit in the middle of a run. */
    @Test
    void theProbeClientIsPublicAndAsksForNoConsent() {
        RegisteredClient client =
                registeredClientRepository.findByClientId(properties.freshnessClient().clientId());

        assertThat(client).isNotNull();
        assertThat(client.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(client.getAuthorizationGrantTypes()).containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(client.getScopes()).contains(OidcScopes.OPENID);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getClientSettings().isRequireAuthorizationConsent()).isFalse();
    }

    @Test
    void thePageSendsAnAnonymousVisitorThroughTheLogin() throws Exception {
        MvcResult result = mockMvc().perform(get("/freshness"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl())
                .endsWith("/oauth2/authorization/" + properties.client().registrationId());
    }

    private MockHttpServletRequest authorizationRequest(String maxAge) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", AUTHORIZE);
        request.setParameter("state", "a-state");
        // Both, because the filter reads the parameter and redirects with the query string.
        request.setQueryString("state=a-state");
        if (!maxAge.isEmpty()) {
            request.setParameter("max_age", maxAge);
            request.setQueryString("state=a-state&max_age=" + maxAge);
        }
        request.getSession(true);
        SecurityContextHolder.getContext().setAuthentication(authenticatedWith(Instant.now()));
        return request;
    }

    private static Authentication authenticatedWith(Instant... issuedAt) {
        List<FactorGrantedAuthority> factors = List.of(
                FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
                        .issuedAt(issuedAt[0]).build(),
                FactorGrantedAuthority.withAuthority(FactorGrantedAuthority.OTT_AUTHORITY)
                        .issuedAt(issuedAt[issuedAt.length - 1]).build());
        return UsernamePasswordAuthenticationToken.authenticated("hendi", null,
                issuedAt.length == 1 ? List.of(factors.get(0)) : factors);
    }
}
