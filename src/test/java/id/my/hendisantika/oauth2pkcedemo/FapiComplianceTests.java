package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.FapiCheck;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectPolicy;
import id.my.hendisantika.oauth2pkcedemo.security.RequestUriPolicy;
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

    @Autowired
    private RequestObjectPolicy requestObjectPolicy;

    @Autowired
    private RequestUriPolicy requestUriPolicy;

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

        // Three: PAR not required server-wide, plain HTTP, and a request object algorithm list that
        // advertises two algorithms the profile does not want.
        assertThat(failures(checks)).isEqualTo(3);
        assertThat(checks).anySatisfy(check -> {
            assertThat(check.requirement()).contains("pushed authorization requests");
            assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
        });
    }

    /**
     * FAPI 2.0 dropped the signed request object in favour of a pushed one, so the row is reported
     * as not applicable rather than as a pass or a gap - and it still says what this server holds.
     */
    @Test
    void theRequestObjectRowSaysWhichProfileAsksForIt() {
        List<FapiCheck> checks = fapiComplianceService.serverChecks();

        assertThat(checks).anySatisfy(check -> {
            assertThat(check.requirement()).contains("Request objects are signed");
            assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.NOT_APPLICABLE);
            assertThat(check.reference()).contains("FAPI 1.0 Advanced").contains("FAPI 2.0");
            assertThat(check.observed())
                    .contains("require_signed_request_object")
                    .contains("server-wide it is "
                            + requestObjectPolicy.requireSignedRequestObject())
                    .containsPattern("\\d+ of the \\d+ clients below set it");
        });
    }

    /** The same lock, one specification along, and this server does not have that one. */
    @Test
    void theParRowNamesTheRequirementItFails() {
        List<FapiCheck> checks = fapiComplianceService.serverChecks();

        assertThat(checks).anySatisfy(check -> {
            assertThat(check.requirement()).contains("requires pushed authorization requests");
            assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
            assertThat(check.observed())
                    .contains("shall reject authorization requests sent without")
                    .contains("§5's server-wide require_pushed_authorization_requests is false")
                    .containsPattern("set by \\d+ of the \\d+ clients below");
        });
    }

    /**
     * The row no FAPI profile asks for, kept because thirty-two of the client rows lean on it. It
     * reads the switch live, so it is asserted in both positions.
     */
    @Test
    void theRequestUriRegistrationRowTracksTheSwitchAndNamesItsSpec() {
        assertThat(requestUriPolicy.requireRegistration()).isTrue();
        assertThat(fapiComplianceService.serverChecks()).anySatisfy(check -> {
            assertThat(check.requirement()).contains("Fetched request_uris must be pre-registered");
            assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
            assertThat(check.reference()).contains("RFC 9101").contains("no FAPI profile names it");
            assertThat(check.observed())
                    .contains("does not point to an unexpected location")
                    .contains("Discovery makes the default false")
                    .containsPattern("\\d+ of the \\d+ clients below have registered a URL");
        });

        boolean previous = requestUriPolicy.requireRegistration(false);
        try {
            assertThat(fapiComplianceService.serverChecks()).anySatisfy(check -> {
                assertThat(check.requirement()).contains("Fetched request_uris must be pre-registered");
                assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
            });
        } finally {
            requestUriPolicy.requireRegistration(previous);
        }
    }

    /**
     * §8.6 binds "both clients and authorization servers", so the per-client rows are only half of
     * it. The server half is the list it advertises, and this server advertises two algorithms the
     * profile does not want - deliberately, which the row has to say rather than imply an oversight.
     */
    @Test
    void theAdvertisedAlgorithmListIsJudgedByTheSameRuleAsTheClients() {
        assertThat(fapiComplianceService.serverChecks()).anySatisfy(check -> {
            assertThat(check.requirement()).contains("Advertised request object signing algorithms");
            assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
            assertThat(check.reference()).contains("FAPI 1.0 Advanced").contains("FAPI 2.0");
            assertThat(check.observed())
                    .contains("request_object_signing_alg_values_supported")
                    .contains("RS256")
                    .contains("none")
                    .contains("both clients and authorization servers")
                    .contains("deliberate");
        });
    }

    /** What the row reports has to be what the discovery document actually publishes. */
    @Test
    void theRowNamesTheListThatIsActuallyAdvertised() {
        FapiCheck check = fapiComplianceService.serverChecks().stream()
                .filter(c -> c.requirement().contains("Advertised request object signing algorithms"))
                .findFirst()
                .orElseThrow();

        assertThat(check.observed()).contains(
                JwtSecuredAuthorizationRequestFilter.SUPPORTED_SIGNING_ALGS.stream().sorted().toList()
                        .toString());
    }

    /**
     * The encryption half of the advertised-algorithms idea. It passes where the signing one fails,
     * and the reason is what each page had to demonstrate rather than a difference in the rules.
     */
    @Test
    void theAdvertisedEncryptionListExcludesTheForbiddenAlgorithm() {
        assertThat(JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS)
                .doesNotContain("RSA1_5");

        assertThat(fapiComplianceService.serverChecks()).anySatisfy(check -> {
            assertThat(check.requirement())
                    .contains("Advertised request object encryption algorithms exclude RSA1_5");
            assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
            assertThat(check.reference()).contains("FAPI 1.0 Advanced");
            assertThat(check.observed())
                    .contains("request_object_encryption_alg_values_supported")
                    .contains(JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS.stream()
                            .sorted().toList().toString())
                    .contains("binds both sides");
        });
    }

    /**
     * The pairing that makes both rows worth reading: the same profile section binds the server and
     * the client, and here the server passes while a client fails.
     */
    @Test
    void theServerPassesTheEncryptionRuleThatOneOfItsClientsFails() {
        FapiCheck server = fapiComplianceService.serverChecks().stream()
                .filter(c -> c.requirement().contains("encryption algorithms exclude RSA1_5"))
                .findFirst()
                .orElseThrow();
        FapiCheck client = encryptionCheckFor(fapiComplianceService.clientChecks(),
                properties.jarRsa15Client());

        assertThat(server.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
        assertThat(client.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
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

        // Thirty-four clients, each demonstrating something; the page should hide none of them.
        assertThat(checks).hasSize(34);
        assertThat(checks.values()).allSatisfy(clientChecks -> assertThat(clientChecks).hasSize(8));
    }

    /**
     * Both profiles name the same JWS algorithms, so the row is judged from the registration - the
     * only thing that says what a request object from this client may ever be signed with.
     */
    @Test
    void theSigningAlgorithmRowFollowsWhatEachClientRegistered() {
        Map<String, List<FapiCheck>> checks = fapiComplianceService.clientChecks();

        assertThat(algorithmCheckFor(checks, properties.jarPsClient()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
                    assertThat(check.reference()).contains("FAPI 1.0 Advanced").contains("FAPI 2.0");
                    assertThat(check.observed()).contains("PS256");
                });

        // "shall not use none", in both profiles, and this server accepts it anyway.
        assertThat(algorithmCheckFor(checks, properties.jarNoneClient()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
                    assertThat(check.observed()).contains("none").contains("shall not be used");
                });

        // Registered nothing, so there is nothing of the client's to judge - and the row says which
        // algorithm this server would fall back to rather than leaving that unsaid.
        assertThat(algorithmCheckFor(checks, properties.client()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.NOT_APPLICABLE);
                    assertThat(check.observed())
                            .contains("No request_object_signing_alg registered")
                            .contains(JwtSecuredAuthorizationRequestFilter.DEFAULT_SIGNING_ALG);
                });
    }

    /**
     * The profile's list of algorithms and this server's are not the same list, and the client that
     * sits in the gap should pass the row while being told its request objects are refused.
     */
    @Test
    void aClientCanSatisfyTheProfileWithAnAlgorithmThisServerWillNotVerify() {
        FapiCheck check = algorithmCheckFor(fapiComplianceService.clientChecks(),
                properties.jarEsClient());

        assertThat(JwtSecuredAuthorizationRequestFilter.SUPPORTED_SIGNING_ALGS)
                .doesNotContain("ES256");
        assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
        assertThat(check.observed()).contains("ES256").contains("refused");
    }

    /**
     * Section 8.6.1 forbids one algorithm and lists none, so everything that is not RSA1_5 passes -
     * a different shape from the signing row, which has a list to be on.
     */
    @Test
    void theEncryptionRowForbidsOneAlgorithmRatherThanRequiringAList() {
        Map<String, List<FapiCheck>> checks = fapiComplianceService.clientChecks();

        assertThat(encryptionCheckFor(checks, properties.jarRsa15Client()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
                    assertThat(check.reference()).contains("FAPI 1.0 Advanced");
                    assertThat(check.observed()).contains("RSA1_5");
                });

        // Neither is on any FAPI list; neither is forbidden either, which is the whole test.
        assertThat(encryptionCheckFor(checks, properties.jarOaep512Client()).outcome())
                .isEqualTo(FapiCheck.Outcome.PASS);
        assertThat(encryptionCheckFor(checks, properties.jarGcmClient()).outcome())
                .isEqualTo(FapiCheck.Outcome.PASS);
    }

    /**
     * Registering nothing is not the same as registering a default here, and the row should say what
     * the registration spec says rather than borrowing the signing row's wording.
     */
    @Test
    void anUndeclaredEncryptionAlgorithmIsNotTreatedAsADefault() {
        FapiCheck check = encryptionCheckFor(fapiComplianceService.clientChecks(),
                properties.client());

        assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.NOT_APPLICABLE);
        assertThat(check.observed()).contains("not declaring whether it might encrypt");
    }

    /**
     * The client that registered a content encryption method and nothing to wrap its key with. The
     * registration spec forbids it, so the row should name that rather than report it as a client
     * that said nothing.
     */
    @Test
    void theIncompleteEncryptionRegistrationIsCalledOutAsIncomplete() {
        FapiCheck check = encryptionCheckFor(fapiComplianceService.clientChecks(),
                properties.jarEncOnlyClient());

        assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.NOT_APPLICABLE);
        assertThat(check.observed())
                .contains("no request_object_encryption_alg")
                .contains("registration spec does not allow");
    }

    /** RSA1_5 fails the profile and is refused here anyway - the two happen to agree. */
    @Test
    void theForbiddenEncryptionAlgorithmIsOneThisServerAlsoRefuses() {
        assertThat(JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS)
                .doesNotContain("RSA1_5");
    }

    /**
     * No FAPI profile names a content encryption method, so the row asks what RFC 8725 §3.1 asks -
     * whether the registered enc is in a supported set at all - and a registration naming one this
     * server will not decrypt is a real failure rather than a curiosity.
     */
    @Test
    void theEncRowFailsAMethodThisServerWillNotDecrypt() {
        Map<String, List<FapiCheck>> checks = fapiComplianceService.clientChecks();

        assertThat(encMethodCheckFor(checks, properties.jarUnsupportedEncClient()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
                    assertThat(check.reference()).contains("RFC 8725");
                    assertThat(check.observed()).contains("A192CBC-HS384").contains("supported set");
                });

        assertThat(encMethodCheckFor(checks, properties.jarGcmClient()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
                    assertThat(check.observed()).contains("A256GCM");
                });
    }

    /**
     * The one default in this trio that depends on its sibling: the registration spec supplies
     * A128CBC-HS256 only when an alg was registered, so a client with an alg and no enc has a
     * declared method and a client with neither does not.
     */
    @Test
    void theEncDefaultAppliesOnlyWhenAnAlgorithmWasRegistered() {
        Map<String, List<FapiCheck>> checks = fapiComplianceService.clientChecks();

        assertThat(encMethodCheckFor(checks, properties.jarOaep512Client()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
                    assertThat(check.observed())
                            .contains(JwtSecuredAuthorizationRequestFilter.DEFAULT_ENCRYPTION_ENC)
                            .contains("because an alg is present");
                });

        assertThat(encMethodCheckFor(checks, properties.client()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.NOT_APPLICABLE);
                    assertThat(check.observed()).contains("Neither half");
                });
    }

    /**
     * The mechanism FAPI 1.0 Advanced blessed and FAPI 2.0 designed out, so the row cites both and
     * fails the two clients that registered URLs to be fetched from.
     */
    @Test
    void thePreRegisteredRequestUriRowFailsTheClientsThatRegisteredOne() {
        Map<String, List<FapiCheck>> checks = fapiComplianceService.clientChecks();

        assertThat(requestUriCheckFor(checks, properties.fetchedRequestClient()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
                    assertThat(check.reference()).contains("FAPI 2.0").contains("FAPI 1.0 Advanced");
                    assertThat(check.observed()).contains("Registered 3 request_uris");
                });

        // One URL, registered to a different client so the fetching page can show the list is per
        // client. It fails the same row, and the count in the text has to follow the registration.
        assertThat(requestUriCheckFor(checks, properties.confidentialClient()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
                    assertThat(check.observed()).contains("Registered 1 request_uris");
                });
    }

    /**
     * Registering none of them only means something while an unregistered URL cannot be used
     * instead, so the row reads the switch rather than assuming where it is left.
     */
    @Test
    void theRowForAClientWithNoRequestUrisFollowsTheRegistrationSwitch() {
        assertThat(requestUriPolicy.requireRegistration()).isTrue();
        assertThat(requestUriCheckFor(fapiComplianceService.clientChecks(), properties.client()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
                    assertThat(check.observed()).contains("require_request_uri_registration is true");
                });

        boolean previous = requestUriPolicy.requireRegistration(false);
        try {
            assertThat(requestUriCheckFor(fapiComplianceService.clientChecks(), properties.client()))
                    .satisfies(check -> {
                        assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
                        assertThat(check.observed()).contains("could still name any https URL");
                    });
        } finally {
            requestUriPolicy.requireRegistration(previous);
        }
    }

    private FapiCheck requestUriCheckFor(Map<String, List<FapiCheck>> checks,
                                         DemoProperties.Client configured) {
        return rowFor(checks, configured, "pre-registered request_uri");
    }

    private FapiCheck encMethodCheckFor(Map<String, List<FapiCheck>> checks,
                                        DemoProperties.Client configured) {
        return rowFor(checks, configured, "enc is one this server supports");
    }

    private FapiCheck encryptionCheckFor(Map<String, List<FapiCheck>> checks,
                                         DemoProperties.Client configured) {
        return rowFor(checks, configured, "RSA1_5");
    }

    private FapiCheck algorithmCheckFor(Map<String, List<FapiCheck>> checks,
                                        DemoProperties.Client configured) {
        return rowFor(checks, configured, "PS256 or ES256");
    }

    private FapiCheck rowFor(Map<String, List<FapiCheck>> checks,
                             DemoProperties.Client configured, String requirementFragment) {
        RegisteredClient client = registeredClientRepository.findByClientId(configured.clientId());
        assertThat(client).isNotNull();

        return checks.get(client.getClientName()).stream()
                .filter(check -> check.requirement().contains(requirementFragment))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "no '" + requirementFragment + "' row for " + client.getClientName()));
    }

    @Test
    void theFapiPageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/fapi")).andExpect(status().isOk());
    }
}
