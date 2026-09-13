package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.IdTokenBindingRun;
import id.my.hendisantika.oauth2pkcedemo.security.IdTokenCheck;
import id.my.hendisantika.oauth2pkcedemo.service.IdTokenBindingService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.lang.reflect.Method;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

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
 * Time: 11.40
 */
@SpringBootTest
class IdTokenBindingTests extends AbstractMySqlIntegrationTest {

    private static final String ACCESS_TOKEN = "an-access-token-this-id-token-came-with";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private IdTokenBindingService idTokenBindingService;

    @Autowired
    private JWKSource<SecurityContext> jwkSource;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /**
     * OpenID Connect Core appendix A.3 publishes this pair. Getting it right matters because the
     * page shows what the absent claim would have contained.
     */
    @Test
    void theAccessTokenHashMatchesTheSpecificationsWorkedExample() {
        assertThat(IdTokenBindingService.atHash("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"))
                .isEqualTo("77QmUPtjPfzWtF2AnpK9RQ");
    }

    /**
     * The reason at_hash cannot be checked even if it were emitted: Spring Security's validator
     * takes the ID token and nothing else, so no access token is in scope to compare it against.
     */
    @Test
    void theValidatorHasNoAccessTokenToCompareAgainst() {
        List<Method> validates = Arrays.stream(OidcIdTokenValidator.class.getDeclaredMethods())
                .filter(method -> method.getName().equals("validate"))
                // The compiler adds a bridge taking OAuth2Token for the interface; the declared one
                // is the contract.
                .filter(method -> !method.isBridge())
                .toList();

        assertThat(validates).hasSize(1);
        assertThat(validates.get(0).getParameterTypes()).containsExactly(Jwt.class);
    }

    /** An ID token with no at_hash: two substitutions caught, two not. */
    @Test
    void anIdTokenWithoutAtHashCannotNoticeASubstitutedAccessToken() {
        IdTokenBindingRun run = run(null);

        assertThat(run.carriesAtHash()).isFalse();
        assertThat(run.carriesConfirmation()).isFalse();
        assertThat(run.checks()).extracting(IdTokenCheck::outcome)
                .containsExactly("accepted", "refused", "refused", "accepted", "accepted");
        assertThat(run.gaps()).isEqualTo(2);
        // The hash the claim would have carried is computed anyway, so the page can show it.
        assertThat(run.atHashOfIssuedToken()).isEqualTo(IdTokenBindingService.atHash(ACCESS_TOKEN));
    }

    /** The two refusals, and what each of them read. */
    @Test
    void theClaimsThatDoBindItSayWhereItBelongs() {
        List<IdTokenCheck> checks = run(null).checks();

        assertThat(checks.get(1).label()).isEqualTo("Replayed at another client");
        assertThat(checks.get(1).detail()).contains("aud");
        assertThat(checks.get(1).isCaught()).isTrue();
        assertThat(checks.get(2).detail()).startsWith("invalid_nonce");
        assertThat(checks.get(2).isCaught()).isTrue();
    }

    /**
     * What the missing claim would have done. With an at_hash naming the token it was issued with
     * the substitution is caught; with one naming a different token it is refused outright.
     */
    @Test
    void anAtHashWouldHaveNoticed() {
        assertThat(run(IdTokenBindingService.atHash(ACCESS_TOKEN)).checks().get(3).outcome())
                .isEqualTo("accepted");

        IdTokenCheck substituted = run(IdTokenBindingService.atHash("a-different-access-token"))
                .checks().get(3);

        assertThat(substituted.outcome()).isEqualTo("refused");
        assertThat(substituted.isCaught()).isTrue();
    }

    @Test
    void thePageSendsAnAnonymousVisitorThroughTheLogin() throws Exception {
        MvcResult result = mockMvc().perform(get("/idtoken-binding"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl())
                .endsWith("/oauth2/authorization/" + properties.client().registrationId());
        // A session with no ID token to examine is sent back to the page, not to a 500.
        mockMvc().perform(post("/idtoken-binding").with(csrf()))
                .andExpect(status().is3xxRedirection());
    }

    /** A genuine ID token, signed by the server's own key so the service's decoder accepts it. */
    private IdTokenBindingRun run(String atHash) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(properties.issuerUri())
                .subject("hendi")
                .audience(List.of(properties.client().clientId()))
                .issuedAt(now)
                .expiresAt(now.plus(5, ChronoUnit.MINUTES))
                .claim("azp", properties.client().clientId())
                .claim("nonce", "a-hash-of-the-nonce-the-client-kept");
        if (atHash != null) {
            claims.claim("at_hash", atHash);
        }
        Jwt idToken = new NimbusJwtEncoder(jwkSource).encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).build(), claims.build()));

        return idTokenBindingService.run(
                new OidcIdToken(idToken.getTokenValue(), idToken.getIssuedAt(),
                        idToken.getExpiresAt(), Map.copyOf(idToken.getClaims())),
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, ACCESS_TOKEN, now,
                        now.plus(5, ChronoUnit.MINUTES)),
                properties.client().registrationId());
    }
}
