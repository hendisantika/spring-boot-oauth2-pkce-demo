package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.service.AuthorizationServerMetadataService;
import id.my.hendisantika.oauth2pkcedemo.service.DynamicClientRegistrationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
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
 * Date: 13/09/26
 * Time: 19.14
 */
@SpringBootTest
class DynamicClientRegistrationTests extends AbstractMySqlIntegrationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String REGISTRATION_URI = "/connect/register";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private DynamicClientRegistrationService registrationService;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    private String basicAuthHeader() {
        DemoProperties.Client registrar = properties.registrarClient();
        String credentials = registrar.clientId() + ":" + registrar.clientSecret();
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    /** A client credentials token carrying exactly the scopes named. */
    @SuppressWarnings("unchecked")
    private String token(String scope) throws Exception {
        String body = mockMvc().perform(post("/oauth2/token")
                        .header("Authorization", basicAuthHeader())
                        .param("grant_type", AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                        .param("scope", scope))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return String.valueOf(MAPPER.readValue(body, Map.class).get("access_token"));
    }

    private ResultActions registerWith(String accessToken, Map<String, Object> metadata)
            throws Exception {
        return mockMvc().perform(post(REGISTRATION_URI)
                .headers(headers -> {
                    if (accessToken != null) {
                        headers.setBearerAuth(accessToken);
                    }
                })
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(MAPPER.writeValueAsString(metadata)));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> registerSuccessfully() throws Exception {
        String body = registerWith(token(DynamicClientRegistrationService.CREATE_SCOPE),
                registrationService.clientMetadata())
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return MAPPER.readValue(body, Map.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    void theEndpointIsNamedByBothMetadataDocuments() throws Exception {
        for (String suffix : List.of(AuthorizationServerMetadataService.OAUTH_SUFFIX,
                AuthorizationServerMetadataService.OIDC_SUFFIX)) {
            String body = mockMvc().perform(get("/.well-known/" + suffix))
                    .andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsString();
            assertThat(MAPPER.readValue(body, Map.class))
                    .as("%s", suffix)
                    .containsEntry("registration_endpoint", registrationService.registrationEndpoint());
        }
    }

    @Test
    void registeringWithoutATokenIsRefused() throws Exception {
        registerWith(null, registrationService.clientMetadata())
                .andExpect(status().isUnauthorized());
    }

    /**
     * The endpoint asks for exactly {@code client.create}. A token that carries more is rejected
     * rather than narrowed, which is worth knowing before wondering why a perfectly good token does
     * not work.
     */
    @Test
    void aTokenCarryingMoreThanTheRequiredScopeIsRefused() throws Exception {
        String broadToken = token(DynamicClientRegistrationService.CREATE_SCOPE + " "
                + DynamicClientRegistrationService.READ_SCOPE);

        registerWith(broadToken, registrationService.clientMetadata())
                .andExpect(status().isUnauthorized());
    }

    @Test
    void aWellFormedRegistrationIssuesCredentials() throws Exception {
        Map<String, Object> issued = registerSuccessfully();

        assertThat(issued).containsKeys("client_id", "client_secret", "registration_access_token",
                "registration_client_uri", "client_id_issued_at");
        assertThat(registeredClientRepository.findByClientId(String.valueOf(issued.get("client_id"))))
                .isNotNull();
    }

    /** RFC 7591 section 3 calls it an initial access token; this server spends it on one use. */
    @Test
    void theInitialAccessTokenIsSpentByTheRegistrationItAuthorises() throws Exception {
        String initialAccessToken = token(DynamicClientRegistrationService.CREATE_SCOPE);

        registerWith(initialAccessToken, registrationService.clientMetadata())
                .andExpect(status().isCreated());
        registerWith(initialAccessToken, registrationService.clientMetadata())
                .andExpect(status().isUnauthorized());
    }

    /**
     * RFC 7591 section 2 defines a scope field. This server refuses it outright: a client that named
     * its own scopes would be granting itself authority.
     */
    @Test
    void aRegistrationMayNotAskForScopes() throws Exception {
        Map<String, Object> metadata = new LinkedHashMap<>(registrationService.clientMetadata());
        metadata.put("scope", "openid profile");

        String body = registerWith(token(DynamicClientRegistrationService.CREATE_SCOPE), metadata)
                .andExpect(status().isBadRequest())
                .andReturn().getResponse().getContentAsString();
        assertThat(body).contains("invalid_scope");
    }

    /** The registering party asked for neither, and gets both. */
    @Test
    void theServerImposesItsOwnSecurityPostureOnWhatItRegisters() throws Exception {
        Map<String, Object> issued = registerSuccessfully();

        RegisteredClient client =
                registeredClientRepository.findByClientId(String.valueOf(issued.get("client_id")));
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getClientSettings().isRequireAuthorizationConsent()).isTrue();
        // An identity, not authority: it was not allowed to ask for a scope, so it has none.
        assertThat(client.getScopes()).isEmpty();
    }

    /** RFC 7592: the registration reads back with the token the registration handed out. */
    @Test
    void theRegistrationCanBeReadBackWithItsOwnToken() throws Exception {
        Map<String, Object> issued = registerSuccessfully();
        String uri = String.valueOf(issued.get("registration_client_uri"))
                .substring(properties.issuerUri().length());

        mockMvc().perform(get(uri)
                        .headers(headers -> headers.setBearerAuth(
                                String.valueOf(issued.get("registration_access_token"))))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
        mockMvc().perform(get(uri).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void theRegistrarMayOnlyMintTokensForItself() {
        RegisteredClient registrar =
                registeredClientRepository.findByClientId(properties.registrarClient().clientId());

        assertThat(registrar).isNotNull();
        assertThat(registrar.getAuthorizationGrantTypes())
                .containsExactly(AuthorizationGrantType.CLIENT_CREDENTIALS);
        assertThat(registrar.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(registrar.getScopes()).containsExactlyInAnyOrder(
                DynamicClientRegistrationService.CREATE_SCOPE,
                DynamicClientRegistrationService.READ_SCOPE);
    }

    @Test
    void theRegistrationPageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/dynamic-registration")).andExpect(status().isOk());
    }
}
