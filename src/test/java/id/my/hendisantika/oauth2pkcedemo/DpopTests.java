package id.my.hendisantika.oauth2pkcedemo;

import com.nimbusds.jwt.JWTParser;
import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.DpopKeyPair;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Map;

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
 * Time: 14.24
 */
@SpringBootTest
class DpopTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    @Test
    void aProofIsTypedAndCarriesItsOwnPublicKey() throws Exception {
        DpopKeyPair key = DpopKeyPair.generate();
        String proof = key.proof("POST", "http://localhost:8080/oauth2/token", null);

        var parsed = JWTParser.parse(proof);
        // RFC 9449 section 4.2: the explicit type stops a proof being mistaken for another JWT, and
        // the embedded key is what lets the server check the binding.
        assertThat(parsed.getHeader().getType().toString()).isEqualTo("dpop+jwt");
        assertThat(parsed.getHeader().toJSONObject()).containsKey("jwk");

        Map<String, Object> claims = parsed.getJWTClaimsSet().getClaims();
        assertThat(claims).containsEntry("htm", "POST")
                .containsEntry("htu", "http://localhost:8080/oauth2/token")
                .containsKeys("jti", "iat");
        // No token to bind to yet, so no ath.
        assertThat(claims).doesNotContainKey("ath");
    }

    @Test
    void aProofForAResourceRequestBindsToTheTokenAsWell() throws Exception {
        DpopKeyPair key = DpopKeyPair.generate();
        String proof = key.proof("GET", "http://localhost:8080/api/me", "an-access-token");

        Map<String, Object> claims = JWTParser.parse(proof).getJWTClaimsSet().getClaims();
        // ath ties the proof to one specific token, not merely to the key.
        assertThat(claims).containsKey("ath");
        assertThat(claims.get("ath")).isNotEqualTo("an-access-token");
    }

    @Test
    void everyProofIsDistinct() {
        DpopKeyPair key = DpopKeyPair.generate();
        String first = key.proof("GET", "http://localhost:8080/api/me", null);
        String second = key.proof("GET", "http://localhost:8080/api/me", null);

        // A repeated jti is what lets a server detect a replay, so proofs must not be reusable.
        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void separateKeysProduceSeparateThumbprints() {
        assertThat(DpopKeyPair.generate().thumbprint())
                .isNotEqualTo(DpopKeyPair.generate().thumbprint());
    }

    @Test
    void theProtectedApiRefusesAnUnauthenticatedCall() throws Exception {
        mockMvc().perform(get("/api/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void theProtectedApiRefusesAnArbitraryBearerToken() throws Exception {
        // The chain resolves no bearer token at all, so this endpoint cannot be reached without a
        // proof even with a token that would otherwise be valid.
        mockMvc().perform(get("/api/me").header("Authorization", "Bearer not-a-real-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void theDpopPageRequiresAnAuthenticatedSession() throws Exception {
        var result = mockMvc().perform(get("/dpop")).andExpect(status().is3xxRedirection()).andReturn();
        assertThat(result.getResponse().getRedirectedUrl())
                .endsWith("/oauth2/authorization/" + properties.client().registrationId());
    }
}
