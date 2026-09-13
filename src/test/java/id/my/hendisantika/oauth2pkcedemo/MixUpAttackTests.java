package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.MixUpController;
import id.my.hendisantika.oauth2pkcedemo.security.IssuerIdentifierResponseHandler;
import id.my.hendisantika.oauth2pkcedemo.security.MixUpRun;
import id.my.hendisantika.oauth2pkcedemo.security.PendingMixUp;
import id.my.hendisantika.oauth2pkcedemo.service.MixUpAttackerService;
import id.my.hendisantika.oauth2pkcedemo.service.MixUpService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;
import java.net.URLEncoder;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 18.33
 */
@SpringBootTest
class MixUpAttackTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private MixUpService mixUpService;

    @Autowired
    private MixUpAttackerService attacker;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    private String encodedIssuer() {
        return URLEncoder.encode(properties.issuerUri(), StandardCharsets.UTF_8);
    }

    @Test
    void theAuthorizationResponseSaysWhichServerSentIt() throws Exception {
        MvcResult result = mockMvc().perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", properties.mixUpClient().clientId())
                        .queryParam("redirect_uri", redirectUri())
                        .queryParam("scope", "openid profile")
                        .queryParam("state", "a-state-the-attacker-forwarded")
                        .queryParam("code_challenge", CODE_CHALLENGE)
                        .queryParam("code_challenge_method", "S256")
                        .with(user("hendi")))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl())
                .contains("code=")
                .contains("state=a-state-the-attacker-forwarded")
                .contains(IssuerIdentifierResponseHandler.ISS + "=" + encodedIssuer());
    }

    /** RFC 9207 section 2.1: an error response has to be attributable too. */
    @Test
    void anErrorResponseSaysSoAsWell() throws Exception {
        MvcResult result = mockMvc().perform(get("/oauth2/authorize")
                        .queryParam("response_type", "code")
                        .queryParam("client_id", properties.mixUpClient().clientId())
                        .queryParam("redirect_uri", redirectUri())
                        .queryParam("scope", "a.scope.this.client.does.not.have")
                        .queryParam("state", "a-state")
                        .queryParam("code_challenge", CODE_CHALLENGE)
                        .queryParam("code_challenge_method", "S256")
                        .with(user("hendi")))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(result.getResponse().getRedirectedUrl())
                .contains("error=invalid_scope")
                .contains(IssuerIdentifierResponseHandler.ISS + "=" + encodedIssuer());
    }

    @Test
    void theDiscoveryDocumentAdvertisesTheParameter() throws Exception {
        mockMvc().perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$." + IssuerIdentifierResponseHandler.ISS_PARAMETER_SUPPORTED)
                        .value(true));
    }

    /**
     * The attack in one assertion: everything the client wrote down survives the detour, so what
     * comes back matches the note it kept - including the state that is supposed to tie a response
     * to a request.
     */
    @Test
    void theAttackerForwardsTheRequestUnderTheHonestClientsIdentity() {
        PendingMixUp pending = mixUpService.start(true);
        Map<String, String> asSent = mixUpService.authorizationParameters(pending);

        String forwarded = attacker.mixUpRedirect(asSent);

        assertThat(forwarded).startsWith(properties.issuerUri() + "/oauth2/authorize");
        assertThat(forwarded).contains("client_id=" + properties.mixUpClient().clientId());
        assertThat(forwarded).contains("state=" + pending.state());
        assertThat(forwarded).contains("code_challenge=" + pending.codeChallenge());
        // The client never asked to be sent here, and nothing it can see has changed.
        assertThat(asSent).doesNotContainValue(properties.mixUpClient().clientId());
    }

    @Test
    void theClientStartsOutExpectingTheServerTheUserPicked() {
        PendingMixUp pending = mixUpService.start(true);

        assertThat(pending.expectedIssuer()).isEqualTo(attacker.issuer());
        assertThat(pending.expectedIssuer()).isNotEqualTo(properties.issuerUri());
    }

    @Test
    void aClientThatChecksTheIssuerSendsTheCodeNowhere() {
        PendingMixUp pending = mixUpService.start(true);

        MixUpRun run = mixUpService.redeem(pending, "a-code-from-the-honest-server",
                properties.issuerUri());

        assertThat(run.issuerMatches()).isFalse();
        assertThat(run.codeLeaked()).isFalse();
        assertThat(run.stolenTokenSubject()).isNull();
        assertThat(run.steps()).last().satisfies(step ->
                assertThat(step.what()).contains("never sent anywhere"));
    }

    @Test
    void theMixUpClientIsPublicAndOwnsItsCallback() {
        RegisteredClient client =
                registeredClientRepository.findByClientId(properties.mixUpClient().clientId());

        assertThat(client).isNotNull();
        assertThat(client.getClientSecret()).isNull();
        assertThat(client.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getRedirectUris()).containsExactly(redirectUri());
    }

    @Test
    void theMixUpPageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/mixup")).andExpect(status().isOk());
    }

    /** Same reason as every other page that starts an authorization request of its own. */
    @Test
    void aRunStartedOnTopOfAnExistingOAuth2LoginBeginsAgain() throws Exception {
        mockMvc().perform(get("/mixup/start?check=true").with(oauth2Login()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/mixup/start?check=true"));
    }

    private String redirectUri() {
        return properties.issuerUri() + MixUpController.CALLBACK_URI;
    }
}
