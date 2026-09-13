package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.FapiCheck;
import id.my.hendisantika.oauth2pkcedemo.service.FapiComplianceService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;
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
 * Time: 17.32
 */
@SpringBootTest
class FapiComplianceTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private FapiComplianceService fapiComplianceService;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    private static long failures(List<FapiCheck> checks) {
        return checks.stream().filter(check -> check.outcome() == FapiCheck.Outcome.FAIL).count();
    }

    @Test
    void theFapiClientMeetsEveryClientRequirement() {
        RegisteredClient client = registeredClientRepository.findByClientId(properties.fapiClient().clientId());

        assertThat(client).isNotNull();
        // No shared secret: the profile permits private_key_jwt or mTLS and nothing else.
        assertThat(client.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        assertThat(client.getClientSecret()).isNull();
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getTokenSettings().isX509CertificateBoundAccessTokens()).isTrue();
        assertThat(client.getTokenSettings().isReuseRefreshTokens()).isFalse();

        List<FapiCheck> checks = fapiComplianceService.clientChecks().get(client.getClientName());
        assertThat(failures(checks)).isZero();
    }

    @Test
    void thePublicClientFailsOnAuthenticationAndSenderConstraining() {
        RegisteredClient client = registeredClientRepository.findByClientId(properties.client().clientId());
        List<FapiCheck> checks = fapiComplianceService.clientChecks().get(client.getClientName());

        // It exists to demonstrate a public client, which the profile forbids outright.
        assertThat(failures(checks)).isEqualTo(2);
        assertThat(checks).anySatisfy(check -> {
            assertThat(check.requirement()).contains("private_key_jwt");
            assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
        });
    }

    @Test
    void theCheckerReportsTheServerGapsRatherThanHidingThem() {
        List<FapiCheck> checks = fapiComplianceService.serverChecks();

        // The two that remain: no per-client PAR requirement, and plain HTTP.
        assertThat(failures(checks)).isEqualTo(2);
        assertThat(checks).anySatisfy(check -> {
            assertThat(check.requirement()).contains("pushed authorization requests");
            assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
        });
    }

    @Test
    void theMechanismsTheProfileMandatesAreAllPresent() {
        List<FapiCheck> checks = fapiComplianceService.serverChecks();

        for (String requirement : List.of("Pushed authorization requests", "PKCE S256",
                "Sender-constrained tokens", "private_key_jwt and mTLS", "carries iss")) {
            assertThat(checks)
                    .as("requirement containing '%s'", requirement)
                    .anySatisfy(check -> {
                        assertThat(check.requirement()).contains(requirement);
                        assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
                    });
        }
    }

    @Test
    void everyRegisteredClientIsAccountedFor() {
        Map<String, List<FapiCheck>> checks = fapiComplianceService.clientChecks();

        // Eight clients, each demonstrating something; the page should hide none of them.
        assertThat(checks).hasSize(8);
        assertThat(checks.values()).allSatisfy(clientChecks -> assertThat(clientChecks).hasSize(4));
    }

    @Test
    void theFapiPageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/fapi")).andExpect(status().isOk());
    }
}
