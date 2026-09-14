package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.RequestUriController;
import id.my.hendisantika.oauth2pkcedemo.service.RequestUriService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
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
 * Time: 19.05
 */
@SpringBootTest
class RequestUriLifetimeTests extends AbstractMySqlIntegrationTest {

    private static final OAuth2TokenType STATE_TOKEN_TYPE =
            new OAuth2TokenType(OAuth2ParameterNames.STATE);
    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    @Autowired
    private RequestUriService requestUriService;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /**
     * The value is a prefix, a random part, and the expiry in milliseconds - in plain sight, and
     * part of what the server looks the request up by.
     */
    @Test
    void theReferenceCarriesItsOwnExpiry() throws Exception {
        String requestUri = push();

        assertThat(requestUri).startsWith(RequestUriService.PREFIX).contains(RequestUriService.DELIMITER);
        Instant expiresAt = expiryOf(requestUri);
        assertThat(expiresAt).isAfter(Instant.now())
                .isBefore(Instant.now().plus(Duration.ofMinutes(6)));
        assertThat(requestUriService.stillStored(requestUri)).isTrue();
    }

    /** One-time use is a deletion: the second attempt finds nothing rather than a spent flag. */
    @Test
    void aReferenceIsGoneOnceItHasBeenSpent() throws Exception {
        String requestUri = push();

        MvcResult first = authorize(requestUri, properties.requestUriClient().clientId());

        assertThat(first.getResponse().getStatus()).isEqualTo(302);
        assertThat(first.getResponse().getRedirectedUrl())
                .startsWith(properties.issuerUri() + RequestUriController.CALLBACK_URI)
                .contains("code=");
        assertThat(requestUriService.stillStored(requestUri)).isFalse();

        MvcResult second = authorize(requestUri, properties.requestUriClient().clientId());

        assertThat(second.getResponse().getStatus()).isEqualTo(400);
    }

    /**
     * An expired reference is removed before the refusal is returned, so the first retry is what
     * clears the row rather than merely being told no.
     */
    @Test
    void anExpiredReferenceIsRemovedRatherThanRefusedForever() throws Exception {
        String requestUri = push();
        String aged = ageInPlace(requestUri, Instant.now().minus(Duration.ofMinutes(1)));

        assertThat(requestUriService.stillStored(aged)).isTrue();
        MvcResult result = authorize(aged, properties.requestUriClient().clientId());

        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(requestUriService.stillStored(aged)).isFalse();
    }

    /**
     * Editing the number buys nothing: the expiry is part of the key, so a changed one names
     * nothing at all and the lookup fails before any comparison happens.
     */
    @Test
    void movingTheExpiryOutMakesTheReferenceNameNothing() throws Exception {
        String requestUri = push();
        String extended = RequestUriService.PREFIX + randomPartOf(requestUri) + RequestUriService.DELIMITER
                + expiryOf(requestUri).plus(Duration.ofDays(365)).toEpochMilli();

        assertThat(requestUriService.stillStored(extended)).isFalse();
        MvcResult result = authorize(extended, properties.requestUriClient().clientId());

        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        // The real one is untouched: a failed lookup consumes nothing.
        assertThat(requestUriService.stillStored(requestUri)).isTrue();
    }

    /** The reference travels in the clear, and is still not transferable. */
    @Test
    void anotherClientCannotSpendIt() throws Exception {
        String requestUri = push();

        MvcResult result = authorize(requestUri, properties.client().clientId());

        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(requestUriService.stillStored(requestUri)).isTrue();
    }

    @Test
    void theProbeClientIsConfidentialAndAsksForNoConsent() {
        RegisteredClient client =
                registeredClientRepository.findByClientId(properties.requestUriClient().clientId());

        assertThat(client).isNotNull();
        assertThat(client.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(client.getAuthorizationGrantTypes())
                .containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getClientSettings().isRequireAuthorizationConsent()).isFalse();
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/request-uri")).andExpect(status().isOk());
    }

    @SuppressWarnings("unchecked")
    private String push() throws Exception {
        DemoProperties.Client client = properties.requestUriClient();
        String credentials = client.clientId() + ":" + client.clientSecret();
        MvcResult result = mockMvc().perform(post("/oauth2/par")
                        .header("Authorization", "Basic " + Base64.getEncoder()
                                .encodeToString(credentials.getBytes(StandardCharsets.UTF_8)))
                        .param("response_type", "code")
                        .param("client_id", client.clientId())
                        .param("scope", String.join(" ", client.scopes()))
                        .param("redirect_uri", properties.issuerUri() + RequestUriController.CALLBACK_URI)
                        .param("state", "a-state")
                        .param("code_challenge", CODE_CHALLENGE)
                        .param("code_challenge_method", "S256"))
                .andExpect(status().isCreated())
                .andReturn();

        Map<String, Object> body = new tools.jackson.databind.ObjectMapper()
                .readValue(result.getResponse().getContentAsString(), Map.class);
        return String.valueOf(body.get("request_uri"));
    }

    private MvcResult authorize(String requestUri, String clientId) throws Exception {
        // queryParam, not param: for a GET the authorization endpoint reads the query string and
        // ignores anything only in the parameter map, so param() would arrive as an empty request.
        return mockMvc().perform(get("/oauth2/authorize")
                        .queryParam("client_id", clientId)
                        .queryParam("request_uri", requestUri)
                        .with(user("hendi")))
                .andReturn();
    }

    /** What the page does to avoid waiting five minutes: rewrite the key, not the clock. */
    private String ageInPlace(String requestUri, Instant expiresAt) {
        String state = requestUri.substring(RequestUriService.PREFIX.length());
        OAuth2Authorization stored = authorizationService.findByToken(state, STATE_TOKEN_TYPE);
        String aged = randomPartOf(requestUri) + RequestUriService.DELIMITER + expiresAt.toEpochMilli();
        authorizationService.save(OAuth2Authorization.from(stored)
                .attribute(OAuth2ParameterNames.STATE, aged)
                .build());
        return RequestUriService.PREFIX + aged;
    }

    private static String randomPartOf(String requestUri) {
        String state = requestUri.substring(RequestUriService.PREFIX.length());
        return state.substring(0, state.lastIndexOf(RequestUriService.DELIMITER));
    }

    private static Instant expiryOf(String requestUri) {
        String state = requestUri.substring(RequestUriService.PREFIX.length());
        return Instant.ofEpochMilli(Long.parseLong(state.substring(
                state.lastIndexOf(RequestUriService.DELIMITER) + RequestUriService.DELIMITER.length())));
    }
}
