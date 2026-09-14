package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectClientRegistrationConverters;
import id.my.hendisantika.oauth2pkcedemo.service.RegisteredRequestUriService;
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
 * Date: 18/09/26
 * Time: 09.40
 */
@SpringBootTest
class RegisteredRequestUriTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private DemoProperties properties;

    @Autowired
    private AuthorizationServerSettings settings;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** OpenID Connect Registration section 2: an array, which Spring's converters would drop. */
    @Test
    void aRegistrationRequestCarriesTheListOntoTheClient() {
        RegisteredClient client = RequestObjectClientRegistrationConverters.registeredClient()
                .convert(OidcClientRegistration.withClaims(Map.of(
                        "client_name", "Ad hoc client",
                        "redirect_uris", List.of(properties.issuerUri() + "/login/oauth2/code/adhoc"),
                        "grant_types", List.of("authorization_code"),
                        "response_types", List.of("code"),
                        RequestObjectClientRegistrationConverters.REQUEST_URIS,
                        List.of("https://client.example.org/one.jwt",
                                "https://client.example.org/two.jwt"))).build());

        assertThat(client).isNotNull();
        assertThat(String.valueOf(client.getClientSettings()
                .<Object>getSetting(JwtSecuredAuthorizationRequestFilter.REQUEST_URIS_SETTING)))
                .isEqualTo("https://client.example.org/one.jwt https://client.example.org/two.jwt");
    }

    /** And comes back out as the array it arrived as, rather than as the string it is held in. */
    @Test
    void theRegistrationResponseEchoesTheListAsAList() {
        RegisteredClient stored = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("echo-list-client")
                .clientAuthenticationMethod(org.springframework.security.oauth2.core
                        .ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(org.springframework.security.oauth2.core
                        .AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(properties.issuerUri() + "/login/oauth2/code/adhoc")
                .clientSettings(ClientSettings.builder()
                        .setting(JwtSecuredAuthorizationRequestFilter.REQUEST_URIS_SETTING,
                                "https://client.example.org/one.jwt https://client.example.org/two.jwt")
                        .build())
                .build();

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
                RequestObjectClientRegistrationConverters.REQUEST_URIS))
                .isEqualTo(List.of("https://client.example.org/one.jwt",
                        "https://client.example.org/two.jwt"));
    }

    /** A registration that says nothing about request_uris leaves the setting absent. */
    @Test
    void aRegistrationWithoutTheListIsUnchanged() {
        RegisteredClient client = RequestObjectClientRegistrationConverters.registeredClient()
                .convert(OidcClientRegistration.withClaims(Map.of(
                        "client_name", "Ad hoc client",
                        "redirect_uris", List.of(properties.issuerUri() + "/login/oauth2/code/adhoc"),
                        "grant_types", List.of("authorization_code"),
                        "response_types", List.of("code"))).build());

        assertThat(client).isNotNull();
        assertThat(client.getClientSettings()
                .<Object>getSetting(JwtSecuredAuthorizationRequestFilter.REQUEST_URIS_SETTING))
                .isNull();
    }

    /**
     * The whole string is the registered value. A URI with a content-hash fragment does not register
     * the same URI with a different fragment, or with none.
     */
    @Test
    void theFragmentIsPartOfWhatWasRegistered() throws Exception {
        DemoProperties.Client client = properties.fetchedRequestClient();
        String registered = properties.issuerUri() + "/hosted/request-object.jwt";

        assertThat(refusal(client, registered + RegisteredRequestUriService.CONTENT_HASH_FRAGMENT))
                .contains("not registered for this client");
        assertThat(refusal(client, registered + RegisteredRequestUriService.OTHER_HASH_FRAGMENT))
                .contains("not registered for this client");
    }

    /** Registering nothing is not registering everything. */
    @Test
    void aClientWithNoListMayUseNoUrlAtAll() throws Exception {
        DemoProperties.Client client = properties.confidentialClient();

        assertThat(refusal(client, properties.issuerUri() + "/hosted/request-object.jwt"))
                .contains("not registered for this client");
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/request-uris")).andExpect(status().isOk());
    }

    private String refusal(DemoProperties.Client client, String requestUri) throws Exception {
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", client.clientId());
        query.put("request_uri", requestUri);

        var request = get("/oauth2/authorize").with(user("hendi"));
        query.forEach(request::queryParam);
        MvcResult result = mockMvc().perform(request).andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        return result.getResponse().getContentAsString();
    }
}
