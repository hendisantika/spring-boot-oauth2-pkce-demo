package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.CibaAuthenticationToken;
import id.my.hendisantika.oauth2pkcedemo.security.IssuerIdentifierResponseHandler;
import id.my.hendisantika.oauth2pkcedemo.security.MetadataComparison;
import id.my.hendisantika.oauth2pkcedemo.security.MetadataEntry;
import id.my.hendisantika.oauth2pkcedemo.security.RichAuthorizationDetail;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import id.my.hendisantika.oauth2pkcedemo.service.AuthorizationServerMetadataService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import tools.jackson.databind.ObjectMapper;

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
 * Time: 19.12
 */
@SpringBootTest
class AuthorizationServerMetadataTests extends AbstractMySqlIntegrationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private AuthorizationServerMetadataService metadataService;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> document(String uri) throws Exception {
        String body = mockMvc().perform(get(uri))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return MAPPER.readValue(body, Map.class);
    }

    private Map<String, Object> oauthDocument() throws Exception {
        return document("/.well-known/" + AuthorizationServerMetadataService.OAUTH_SUFFIX);
    }

    private Map<String, Object> oidcDocument() throws Exception {
        return document("/.well-known/" + AuthorizationServerMetadataService.OIDC_SUFFIX);
    }

    @SuppressWarnings("unchecked")
    private static List<String> values(Map<String, Object> document, String field) {
        return (List<String>) document.get(field);
    }

    /** RFC 8414 section 3.1, using the specification's own example. */
    /**
     * Every field this application adds is cited to the specification that defines it. The fallback
     * in describe() is RFC 8414 section 2, which is right only for the fields RFC 8414 itself
     * defines - so an extension reported that way is miscited rather than uncited, and this catches
     * the next one added without an entry.
     */
    @Test
    void everyExtensionFieldSaysWhichSpecificationDefinesIt() throws Exception {
        // Read through MockMvc rather than over HTTP: a test that needs something listening on the
        // issuer's port passes only when the demo happens to be running.
        Map<String, Object> document = document("/.well-known/" 
                + AuthorizationServerMetadataService.OAUTH_SUFFIX);

        assertThat(document).isNotEmpty();
        assertThat(metadataService.describe(document, Map.of()))
                .filteredOn(entry -> "RFC 8414 §2".equals(entry.definedBy()))
                .allSatisfy(entry -> assertThat(entry.name())
                        .as("cited to RFC 8414 §2, which defines only its own fields")
                        .isIn(RFC_8414_FIELDS));
    }

    /** RFC 8414 section 2's own list, which is what the fallback citation is true of. */
    private static final List<String> RFC_8414_FIELDS = List.of("issuer", "authorization_endpoint",
            "token_endpoint", "jwks_uri", "registration_endpoint", "scopes_supported",
            "response_types_supported", "response_modes_supported", "grant_types_supported",
            "token_endpoint_auth_methods_supported",
            "token_endpoint_auth_signing_alg_values_supported", "service_documentation",
            "ui_locales_supported", "op_policy_uri", "op_tos_uri", "revocation_endpoint",
            "revocation_endpoint_auth_methods_supported",
            "revocation_endpoint_auth_signing_alg_values_supported", "introspection_endpoint",
            "introspection_endpoint_auth_methods_supported",
            "introspection_endpoint_auth_signing_alg_values_supported",
            "code_challenge_methods_supported");

    @Test
    void theWellKnownStringGoesBeforeThePathNotAfterIt() {
        assertThat(AuthorizationServerMetadataService.wellKnownUri("https://example.com/issuer1",
                AuthorizationServerMetadataService.OAUTH_SUFFIX))
                .isEqualTo("https://example.com/.well-known/oauth-authorization-server/issuer1");
        // No path component, so there is nothing to insert before.
        assertThat(AuthorizationServerMetadataService.wellKnownUri("https://example.com",
                AuthorizationServerMetadataService.OAUTH_SUFFIX))
                .isEqualTo("https://example.com/.well-known/oauth-authorization-server");
        // "any terminating / MUST be removed before inserting"
        assertThat(AuthorizationServerMetadataService.wellKnownUri("https://example.com/issuer1/",
                AuthorizationServerMetadataService.OAUTH_SUFFIX))
                .isEqualTo("https://example.com/.well-known/oauth-authorization-server/issuer1");
    }

    /** OpenID Connect Discovery appends, and the two rules only differ once there is a path. */
    @Test
    void openIdConnectAppendsTheWellKnownStringInstead() {
        assertThat(AuthorizationServerMetadataService.openIdConnectUri("https://example.com/issuer1",
                AuthorizationServerMetadataService.OIDC_SUFFIX))
                .isEqualTo("https://example.com/issuer1/.well-known/openid-configuration");
        assertThat(AuthorizationServerMetadataService.openIdConnectUri("https://example.com",
                AuthorizationServerMetadataService.OIDC_SUFFIX))
                .isEqualTo(AuthorizationServerMetadataService.wellKnownUri("https://example.com",
                        AuthorizationServerMetadataService.OIDC_SUFFIX));
    }

    @Test
    void everythingRfc8414RequiresIsPublished() throws Exception {
        Map<String, Object> document = oauthDocument();

        assertThat(document).containsKeys("issuer", "authorization_endpoint", "token_endpoint",
                "response_types_supported");
        assertThat(document.get("issuer")).isEqualTo(properties.issuerUri());

        List<MetadataEntry> entries = metadataService.describe(document, oidcDocument());
        assertThat(entries.stream().filter(MetadataEntry::required))
                .as("the four fields the specification demands")
                .hasSize(4);
    }

    /**
     * The additions this application makes, which Spring Authorization Server has no way to know
     * about. A server that implements something and does not say so is no better than one that does
     * not implement it, as far as a client reading metadata is concerned.
     */
    @Test
    void theDocumentDescribesWhatThisApplicationAddedToTheServer() throws Exception {
        Map<String, Object> document = oauthDocument();

        assertThat(values(document, "grant_types_supported"))
                .contains(CibaAuthenticationToken.CIBA_GRANT_TYPE.getValue());
        assertThat(values(document, ServerMetadataCustomizer.AUTHORIZATION_DETAILS_TYPES_SUPPORTED))
                .containsExactlyInAnyOrderElementsOf(RichAuthorizationDetail.SUPPORTED_TYPES);
        assertThat(document.get(IssuerIdentifierResponseHandler.ISS_PARAMETER_SUPPORTED))
                .isEqualTo(true);
        assertThat(values(document, "scopes_supported"))
                .contains("openid", "profile", "email", "api.read", "api.write");
    }

    /** One server, two documents: where they name the same field they have to say the same thing. */
    @Test
    void theTwoDocumentsDoNotContradictEachOther() throws Exception {
        MetadataComparison comparison = metadataService.compare(oauthDocument(), oidcDocument());

        assertThat(comparison.disagreeing()).isEmpty();
        assertThat(comparison.consistent()).isTrue();
        // The OpenID document is the superset: it adds what OpenID Connect defines.
        assertThat(comparison.onlyInOauthDocument()).isEmpty();
        assertThat(comparison.onlyInOidcDocument()).contains("userinfo_endpoint");
    }

    /** No value is named twice, which a document assembled from several sources easily does. */
    @Test
    void noAdvertisedListRepeatsItself() throws Exception {
        for (Map<String, Object> document : List.of(oauthDocument(), oidcDocument())) {
            for (Map.Entry<String, Object> field : document.entrySet()) {
                if (field.getValue() instanceof List<?> values) {
                    assertThat(values).as("%s", field.getKey()).doesNotHaveDuplicates();
                }
            }
        }
    }

    /** RFC 8414 section 3.3: the one check a client owes itself before reading any of the rest. */
    @Test
    void aDocumentNamingAnotherIssuerMustNotBeUsed() throws Exception {
        Map<String, Object> document = oauthDocument();

        assertThat(AuthorizationServerMetadataService.issuerMatches(document, properties.issuerUri()))
                .isTrue();
        assertThat(AuthorizationServerMetadataService.issuerMatches(document,
                AuthorizationServerMetadataService.FOREIGN_ISSUER)).isFalse();
        assertThat(AuthorizationServerMetadataService.issuerMatches(Map.of(), properties.issuerUri()))
                .isFalse();
    }

    @Test
    void theMetadataPageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/metadata")).andExpect(status().isOk());
    }
}
