package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.FapiCheck;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.PushedAuthorizationPolicy;
import id.my.hendisantika.oauth2pkcedemo.security.PushedAuthorizationRequiredFilter;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectPolicy;
import id.my.hendisantika.oauth2pkcedemo.security.RequestUriPolicy;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import id.my.hendisantika.oauth2pkcedemo.service.FapiComplianceService;
import id.my.hendisantika.oauth2pkcedemo.service.RequestUriService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

    @Autowired
    private ServerMetadataCustomizer serverMetadataCustomizer;

    @Autowired
    private PushedAuthorizationPolicy pushedAuthorizationPolicy;

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
        // FAPI 2.0 §5.3.2 binds the client to PAR, so the client built to the profile registers it.
        assertThat(client.getClientSettings()
                .<Object>getSetting(PushedAuthorizationRequiredFilter.REQUIRE_PAR_SETTING))
                .isEqualTo(true);
        assertThat(client.getTokenSettings().isX509CertificateBoundAccessTokens()).isTrue();
        assertThat(client.getTokenSettings().isReuseRefreshTokens()).isFalse();

        List<FapiCheck> checks = fapiComplianceService.clientChecks().get(client.getClientName());
        assertThat(failures(checks)).isZero();
    }

    @Test
    void thePublicClientFailsOnAuthenticationSenderConstrainingAndPar() {
        RegisteredClient client = registeredClientRepository.findByClientId(properties.client().clientId());
        List<FapiCheck> checks = fapiComplianceService.clientChecks().get(client.getClientName());

        // It exists to demonstrate a public client, which the profile forbids outright - and it is
        // bound to neither half of the PAR lock, which §5.3.2 asks of the client itself.
        assertThat(failures(checks)).isEqualTo(3);
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
                    .contains("the documents were read back and say the same")
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
                    .contains("the documents were read back and say the same")
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
                    .contains("the documents were read back and say the same")
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

    /**
     * The third advertised list. No FAPI profile names a content encryption method, so the row
     * borrows the same chain the per-client enc row does and says so.
     */
    @Test
    void theAdvertisedEncSetRowNamesItsBorrowedChain() {
        assertThat(fapiComplianceService.serverChecks()).anySatisfy(check -> {
            assertThat(check.requirement()).contains("request object enc set is closed and advertised");
            assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
            assertThat(check.reference()).contains("RFC 8725").contains("FAPI 2.0");
            assertThat(check.observed())
                    .contains("request_object_encryption_enc_values_supported")
                    .contains(JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_METHODS
                            .stream().sorted().toList().toString())
                    .contains("No FAPI profile names a content encryption method");
        });
    }

    /**
     * The row claims the set is closed and points below for the proof rather than asserting it, so
     * the client it points at had better still be failing for that reason.
     */
    @Test
    void theClosedSetClaimIsBackedByAClientThatFailsForBeingOutsideIt() {
        FapiCheck server = fapiComplianceService.serverChecks().stream()
                .filter(c -> c.requirement().contains("enc set is closed"))
                .findFirst()
                .orElseThrow();
        FapiCheck client = encMethodCheckFor(fapiComplianceService.clientChecks(),
                properties.jarUnsupportedEncClient());

        assertThat(server.observed()).contains("A192CBC-HS384");
        assertThat(client.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
        assertThat(client.observed()).contains("A192CBC-HS384");
        assertThat(JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_METHODS)
                .doesNotContain("A192CBC-HS384");
    }

    /**
     * The correspondence the three advertised rows now rest on: what the documents carry is what the
     * request object filter applies. This is the assertion that fires if a list is ever hardcoded
     * into the customizer instead of derived from the code that enforces it.
     */
    @Test
    void everyAdvertisedAlgorithmListIsTheSetThatIsActuallyEnforced() {
        Map<String, Object> published = serverMetadataCustomizer.publishedClaims();

        Map<String, Set<String>> expected = Map.of(
                ServerMetadataCustomizer.REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED,
                JwtSecuredAuthorizationRequestFilter.SUPPORTED_SIGNING_ALGS,
                ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED,
                JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS,
                ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED,
                JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_METHODS);

        expected.forEach((name, enforced) -> assertThat(
                ServerMetadataCustomizer.disagreement(published, name, enforced))
                .as("%s should be advertised exactly as it is enforced", name)
                .isNull());
    }

    /**
     * The comparison itself, driven through the cases that cannot happen while the documents are
     * built from the constants the filter applies - which is exactly why they need testing here
     * rather than being left to a divergence nobody can currently produce.
     */
    @Test
    void theComparisonCatchesBothWaysADocumentCanLie() {
        String name = ServerMetadataCustomizer.REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED;
        Set<String> enforced = Set.of("PS256", "RS256");

        Map<String, Object> missing = new LinkedHashMap<>();
        assertThat(ServerMetadataCustomizer.disagreement(missing, name, enforced))
                .contains("not in the discovery documents")
                .contains("[PS256, RS256]");

        // Advertising less than is accepted: a client never learns RS256 would have worked.
        Map<String, Object> narrower = new LinkedHashMap<>(Map.of(name, List.of("PS256")));
        assertThat(ServerMetadataCustomizer.disagreement(narrower, name, enforced))
                .contains("advertises [PS256]")
                .contains("enforces [PS256, RS256]");

        // Advertising more than is accepted: the worse direction, since a client plans to use
        // something this server will refuse.
        Map<String, Object> wider =
                new LinkedHashMap<>(Map.of(name, List.of("PS256", "RS256", "ES256")));
        assertThat(ServerMetadataCustomizer.disagreement(wider, name, enforced))
                .contains("advertises [ES256, PS256, RS256]");

        // Order is not disagreement; both sides are sorted before comparing.
        Map<String, Object> reordered =
                new LinkedHashMap<>(Map.of(name, List.of("RS256", "PS256")));
        assertThat(ServerMetadataCustomizer.disagreement(reordered, name, enforced)).isNull();
    }

    /**
     * The server-metadata half: RFC 9126 §5's switch is not only read from the policy, it is checked
     * against what the discovery documents actually carry - the claim the row used to make without
     * verifying.
     */
    @Test
    void theParSwitchIsAdvertisedAsItIsEnforced() {
        Map<String, Object> published = serverMetadataCustomizer.publishedClaims();

        // All three switches, since all three rows now settle this before their citation.
        Map<String, Boolean> enforced = Map.of(
                ServerMetadataCustomizer.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS,
                pushedAuthorizationPolicy.requirePushedRequests(),
                ServerMetadataCustomizer.REQUIRE_SIGNED_REQUEST_OBJECT_METADATA,
                requestObjectPolicy.requireSignedRequestObject(),
                ServerMetadataCustomizer.REQUIRE_REQUEST_URI_REGISTRATION,
                requestUriPolicy.requireRegistration());

        enforced.forEach((name, value) -> {
            assertThat(published).containsKey(name);
            assertThat(ServerMetadataCustomizer.disagreement(published, name, value))
                    .as("%s should be advertised exactly as it is enforced", name)
                    .isNull();
        });

        // And it follows the switch rather than describing a value fixed at startup.
        boolean previous = pushedAuthorizationPolicy.requirePushedRequests(true);
        try {
            assertThat(serverMetadataCustomizer.publishedClaims())
                    .containsEntry(ServerMetadataCustomizer.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS,
                            true);
        } finally {
            pushedAuthorizationPolicy.requirePushedRequests(previous);
        }
    }

    /**
     * The switch comparison, driven through what cannot happen while the documents are built from
     * the policy the code reads. Advertising true while enforcing nothing is the dangerous
     * direction, and the text has to say so rather than reporting a symmetrical mismatch.
     */
    @Test
    void theSwitchComparisonCallsOutThePublishedDefenceThatIsNotApplied() {
        String name = ServerMetadataCustomizer.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS;

        assertThat(ServerMetadataCustomizer.disagreement(new LinkedHashMap<>(), name, true))
                .contains("not in the discovery documents")
                .contains("specification default of false");

        Map<String, Object> claiming = new LinkedHashMap<>(Map.of(name, true));
        assertThat(ServerMetadataCustomizer.disagreement(claiming, name, false))
                .contains("advertises true but this server enforces false")
                .contains("told it is protected when it is not");

        Map<String, Object> silent = new LinkedHashMap<>(Map.of(name, false));
        assertThat(ServerMetadataCustomizer.disagreement(silent, name, true))
                .contains("refused for a rule the documents do not mention");

        assertThat(ServerMetadataCustomizer.disagreement(silent, name, false)).isNull();
    }

    /**
     * The capability the signed-request-object row rests on, and the only §5.2.2 requirement that is
     * a disjunction - by value or by reference, either will do. Both booleans are verified, so a
     * server cannot advertise a way in it does not offer.
     */
    @Test
    void theByValueRowVerifiesBothWaysInAndSaysEitherWouldDo() {
        Map<String, Object> published = serverMetadataCustomizer.publishedClaims();

        assertThat(published).containsEntry(ServerMetadataCustomizer.REQUEST_PARAMETER_SUPPORTED, true);
        assertThat(published)
                .containsEntry(ServerMetadataCustomizer.REQUEST_URI_PARAMETER_SUPPORTED, true);

        assertThat(fapiComplianceService.serverChecks()).anySatisfy(check -> {
            assertThat(check.requirement())
                    .contains("Request objects can be passed by value or by reference");
            assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.NOT_APPLICABLE);
            assertThat(check.reference()).contains("FAPI 1.0 Advanced §5.2.2");
            assertThat(check.observed())
                    .contains("by value with the request parameter or by reference")
                    .contains("read back from the documents")
                    .contains("Discovery defaults the first to false");
        });
    }

    /**
     * The row pairs with the failing PAR row rather than standing alone: on a server meeting §5.3.1
     * the by-value parameter is unreachable whatever this metadata says, and this server does not
     * meet it - so the text has to say the parameter really is reachable here.
     */
    @Test
    void theByValueRowTiesItselfToWhetherParIsRequired() {
        FapiCheck check = fapiComplianceService.serverChecks().stream()
                .filter(c -> c.requirement().contains("passed by value or by reference"))
                .findFirst()
                .orElseThrow();

        assertThat(pushedAuthorizationPolicy.requirePushedRequests()).isFalse();
        assertThat(check.observed())
                .contains("§5.3.1")
                .contains("That row fails here, so it is reachable");
    }

    /**
     * RFC 9126 §5's carve-out is the part of request_uri_parameter_supported that can be got wrong:
     * a server gating all request_uri handling on it would refuse its own pushed references. The
     * row demonstrates the scheme discrimination rather than asserting it, so the test drives the
     * same predicate both ways.
     */
    @Test
    void aPushedReferenceIsNotTreatedAsAUrlToFetch() {
        assertThat(JwtSecuredAuthorizationRequestFilter
                .isFetchedRequestUri(RequestUriService.PREFIX + "anything"))
                .as("a pushed reference must not reach the fetch path")
                .isFalse();
        assertThat(JwtSecuredAuthorizationRequestFilter
                .isFetchedRequestUri("https://client.example/request.jwt"))
                .isTrue();
        assertThat(JwtSecuredAuthorizationRequestFilter.isFetchedRequestUri(null)).isFalse();

        assertThat(fapiComplianceService.serverChecks()).anySatisfy(check -> {
            assertThat(check.requirement()).contains("pushed request_uri ignores the fetch metadata");
            assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
            assertThat(check.reference()).contains("RFC 9126 §5");
            assertThat(check.observed())
                    .contains("regardless of other authorization server metadata")
                    .contains("request_uri_parameter_supported")
                    .contains("require_request_uri_registration")
                    .contains("told apart by scheme");
        });
    }

    /**
     * The carve-out has to hold with the registration switch in either position - that is what
     * "regardless" means - so the row must not follow it the way the fetch row does.
     */
    @Test
    void theCarveOutHoldsWhicheverWayTheRegistrationSwitchIsSet() {
        boolean previous = requestUriPolicy.requireRegistration(false);
        try {
            assertThat(carveOutRow().outcome()).isEqualTo(FapiCheck.Outcome.PASS);
        } finally {
            requestUriPolicy.requireRegistration(previous);
        }
        assertThat(carveOutRow().outcome()).isEqualTo(FapiCheck.Outcome.PASS);
    }

    private FapiCheck carveOutRow() {
        return fapiComplianceService.serverChecks().stream()
                .filter(c -> c.requirement().contains("pushed request_uri ignores"))
                .findFirst()
                .orElseThrow();
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
        assertThat(checks.values()).allSatisfy(clientChecks -> assertThat(clientChecks).hasSize(10));
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

    /**
     * The client half of RFC 9101 §10.5, including the registration that argues with itself: the
     * only algorithm it declared is the one the flag beside it refuses.
     */
    @Test
    void theUnsignedRefusalRowReportsTheContradictoryRegistration() {
        Map<String, List<FapiCheck>> checks = fapiComplianceService.clientChecks();

        assertThat(unsignedCheckFor(checks, properties.jarNoneStrictClient()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
                    assertThat(check.reference()).contains("RFC 9101");
                    assertThat(check.observed())
                            .contains("contradict each other")
                            .contains("no request object it can successfully send");
                });

        // Registered none without the lock, so it is the other side of the same pair and must not
        // be reported as locked down.
        assertThat(unsignedCheckFor(checks, properties.jarNoneClient()).outcome())
                .isEqualTo(FapiCheck.Outcome.NOT_APPLICABLE);
    }

    /**
     * Either half of the lock closes the hole, so a client that registered nothing changes answer
     * when the server-wide switch moves - and must say which half is covering it.
     */
    @Test
    void eitherHalfOfTheLockClosesTheDowngradeForAClient() {
        assertThat(requestObjectPolicy.requireSignedRequestObject()).isFalse();
        assertThat(unsignedCheckFor(fapiComplianceService.clientChecks(), properties.client()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.NOT_APPLICABLE);
                    assertThat(check.observed()).contains("Neither half");
                });

        boolean previous = requestObjectPolicy.requireSignedRequestObject(true);
        try {
            assertThat(unsignedCheckFor(fapiComplianceService.clientChecks(), properties.client()))
                    .satisfies(check -> {
                        assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
                        assertThat(check.observed()).contains("server-wide half is on");
                    });
        } finally {
            requestObjectPolicy.requireSignedRequestObject(previous);
        }
    }

    /**
     * Unlike §10.5's lock, this one has a profile asking for it: FAPI 2.0 §5.3.2 binds the client to
     * PAR directly, so a client bound to nothing is a real failure rather than a shrug.
     */
    @Test
    void thePushedRequestRowFailsAClientThatIsNotBoundToPar() {
        Map<String, List<FapiCheck>> checks = fapiComplianceService.clientChecks();

        assertThat(parCheckFor(checks, properties.parRequiredClient()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
                    assertThat(check.reference()).contains("FAPI 2.0 §5.3.2").contains("RFC 9126 §6");
                });

        assertThat(parCheckFor(checks, properties.client()))
                .satisfies(check -> {
                    assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.FAIL);
                    assertThat(check.observed())
                            .contains("may still push voluntarily")
                            .contains("cannot be confirmed from here");
                });
    }

    /** Either half binds the client, so the server-wide switch moves the unbound rows. */
    @Test
    void theServerWideSwitchCoversClientsThatRegisteredNothing() {
        assertThat(pushedAuthorizationPolicy.requirePushedRequests()).isFalse();

        boolean previous = pushedAuthorizationPolicy.requirePushedRequests(true);
        try {
            assertThat(parCheckFor(fapiComplianceService.clientChecks(), properties.client()))
                    .satisfies(check -> {
                        assertThat(check.outcome()).isEqualTo(FapiCheck.Outcome.PASS);
                        assertThat(check.observed()).contains("server-wide half is on");
                    });
        } finally {
            pushedAuthorizationPolicy.requirePushedRequests(previous);
        }
    }

    private FapiCheck parCheckFor(Map<String, List<FapiCheck>> checks,
                                  DemoProperties.Client configured) {
        return rowFor(checks, configured, "may only start requests through PAR");
    }

    private FapiCheck unsignedCheckFor(Map<String, List<FapiCheck>> checks,
                                       DemoProperties.Client configured) {
        return rowFor(checks, configured, "Unsigned requests are refused");
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
