package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JarRequestSigner;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectClientRegistrationConverters;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectPolicy;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 16/09/26
 * Time: 20.05
 */
@SpringBootTest
class ClientRequiredRequestObjectTests extends AbstractMySqlIntegrationTest {

    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private JarRequestSigner signer;

    @Autowired
    private DemoProperties properties;

    @Autowired
    private RequestObjectPolicy policy;

    @Autowired
    private AuthorizationServerSettings settings;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** The registration converter keeps a metadata name Spring Authorization Server drops. */
    @Test
    void aRegistrationRequestCarriesTheSettingOntoTheClient() {
        RegisteredClient client = RequestObjectClientRegistrationConverters.registeredClient()
                .convert(OidcClientRegistration.withClaims(registrationClaims(Map.of(
                        RequestObjectClientRegistrationConverters.REQUIRE_SIGNED_REQUEST_OBJECT, true,
                        RequestObjectClientRegistrationConverters.REQUEST_OBJECT_SIGNING_ALG,
                        "none"))).build());

        assertThat(client).isNotNull();
        assertThat(client.getClientSettings()
                .<Object>getSetting(JwtSecuredAuthorizationRequestFilter.REQUIRE_SIGNED_SETTING))
                .isEqualTo(true);
        assertThat(client.getClientSettings()
                .<Object>getSetting(JwtSecuredAuthorizationRequestFilter.SIGNING_ALG_SETTING))
                .isEqualTo("none");
    }

    /** A registration that says nothing about request objects is left exactly as it was. */
    @Test
    void aRegistrationWithoutTheSettingsIsUnchanged() {
        RegisteredClient client = RequestObjectClientRegistrationConverters.registeredClient()
                .convert(OidcClientRegistration.withClaims(registrationClaims(Map.of())).build());

        assertThat(client).isNotNull();
        assertThat(client.getClientSettings()
                .<Object>getSetting(JwtSecuredAuthorizationRequestFilter.REQUIRE_SIGNED_SETTING))
                .isNull();
        assertThat(client.getClientSettings()
                .<Object>getSetting(JwtSecuredAuthorizationRequestFilter.SIGNING_ALG_SETTING))
                .isNull();
    }

    /**
     * RFC 7591 section 3.2.1: the response describes the client as the server now holds it. A value
     * kept and not echoed is one the caller cannot confirm.
     */
    @Test
    void theRegistrationResponseEchoesTheSetting() {
        RegisteredClient stored = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("echo-client")
                .clientAuthenticationMethod(org.springframework.security.oauth2.core
                        .ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(org.springframework.security.oauth2.core
                        .AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(properties.issuerUri() + "/login/oauth2/code/adhoc")
                .clientSettings(ClientSettings.builder()
                        .setting(JwtSecuredAuthorizationRequestFilter.REQUIRE_SIGNED_SETTING, true)
                        .setting(JwtSecuredAuthorizationRequestFilter.SIGNING_ALG_SETTING, "none")
                        .build())
                .build();

        // The default converter builds a registration_client_uri from the issuer, which only exists
        // inside a request to the authorization server.
        AuthorizationServerContextHolder.setContext(new AuthorizationServerContext() {
            @Override
            public String getIssuer() {
                return properties.issuerUri();
            }

            @Override
            public AuthorizationServerSettings getAuthorizationServerSettings() {
                return settings;
            }
        });
        OidcClientRegistration registration;
        try {
            registration = RequestObjectClientRegistrationConverters.clientRegistration()
                    .convert(stored);
        } finally {
            AuthorizationServerContextHolder.resetContext();
        }

        assertThat(registration).isNotNull();
        assertThat(registration.<Object>getClaim(
                RequestObjectClientRegistrationConverters.REQUIRE_SIGNED_REQUEST_OBJECT))
                .isEqualTo(true);
        assertThat(registration.<Object>getClaim(
                RequestObjectClientRegistrationConverters.REQUEST_OBJECT_SIGNING_ALG))
                .isEqualTo("none");
    }

    /** The client-side switch stands on its own, with the server-wide one off. */
    @Test
    void theClientSettingRefusesAnOrdinaryRequestWhileTheServerSwitchIsOff() throws Exception {
        assertThat(policy.requireSignedRequestObject()).isFalse();
        DemoProperties.Client client = properties.jarNoneStrictClient();

        assertThat(refusal(parameters(client)))
                .contains("This client registered require_signed_request_object");
    }

    /** And the client next to it, registered without the setting, is untouched. */
    @Test
    void aClientThatRegisteredNothingIsLeftAlone() throws Exception {
        assertThat(authorize(parameters(properties.client()))).doesNotContain("error=");
    }

    /**
     * The pair the page ends on: a client that registered the defence and {@code none} together can
     * send nothing this server will act on, and each half says which rule refused it.
     */
    @Test
    void aClientCanRegisterTwoThingsThatCannotBothBeSatisfied() throws Exception {
        DemoProperties.Client client = properties.jarNoneStrictClient();

        assertThat(refusal(withRequestObject(client, signer.unsigned(client.clientId(),
                properties.issuerUri(), parameters(client)))))
                .contains("This client registered require_signed_request_object");
        assertThat(refusal(withRequestObject(client, signer.sign(client.clientId(),
                properties.issuerUri(), parameters(client)))))
                .contains("signed with RS256")
                .contains("registered none");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/jar-client-required")).andExpect(status().isOk());
    }

    private Map<String, Object> registrationClaims(Map<String, Object> extra) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("client_name", "Ad hoc client");
        claims.put("redirect_uris", List.of(properties.issuerUri() + "/login/oauth2/code/adhoc"));
        claims.put("grant_types", List.of("authorization_code"));
        claims.put("response_types", List.of("code"));
        claims.putAll(extra);
        return claims;
    }

    private MvcResult perform(Map<String, String> query) throws Exception {
        var request = get("/oauth2/authorize").with(user("hendi"));
        query.forEach(request::queryParam);
        return mockMvc().perform(request).andReturn();
    }

    private String authorize(Map<String, String> query) throws Exception {
        MvcResult result = perform(query);
        assertThat(result.getResponse().getStatus()).isEqualTo(302);
        return result.getResponse().getRedirectedUrl();
    }

    private String refusal(Map<String, String> query) throws Exception {
        MvcResult result = perform(query);
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        return result.getResponse().getContentAsString();
    }

    private Map<String, String> withRequestObject(DemoProperties.Client client, String requestObject) {
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", client.clientId());
        query.put("request", requestObject);
        return query;
    }

    private Map<String, String> parameters(DemoProperties.Client client) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("response_type", "code");
        parameters.put("client_id", client.clientId());
        parameters.put("scope", String.join(" ", client.scopes()));
        parameters.put("redirect_uri", properties.issuerUri() + "/login/oauth2/code/"
                + client.registrationId());
        parameters.put("state", "a-state");
        parameters.put("code_challenge", CODE_CHALLENGE);
        parameters.put("code_challenge_method", "S256");
        return parameters;
    }
}
