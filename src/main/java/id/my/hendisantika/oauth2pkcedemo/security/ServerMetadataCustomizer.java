package id.my.hendisantika.oauth2pkcedemo.security;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.CheckSessionIframeController;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.12
 */
public final class ServerMetadataCustomizer {

    /** OpenID Connect Session Management section 3.3. */
    public static final String CHECK_SESSION_IFRAME = "check_session_iframe";

    /** RFC 9396 section 10: the authorization_details types a client may ask for. */
    public static final String AUTHORIZATION_DETAILS_TYPES_SUPPORTED =
            "authorization_details_types_supported";

    /**
     * RFC 9101 section 10.5, as server metadata: the value a deployment starts with. False here so
     * that a client which registered {@code none} can be shown doing it, and published either way -
     * a defence a client cannot read is one it cannot rely on.
     */
    public static final boolean REQUIRE_SIGNED_REQUEST_OBJECT_DEFAULT = false;

    /** RFC 9101 section 10.5. */
    public static final String REQUIRE_SIGNED_REQUEST_OBJECT_METADATA = "require_signed_request_object";

    /** RFC 9101 section 4: what a client may sign a request object with, {@code none} included. */
    public static final String REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED =
            "request_object_signing_alg_values_supported";

    private final AuthorizationServerSettings settings;
    private final DemoProperties properties;

    /** Read on every request rather than captured, so the published value is the live one. */
    private final RequestObjectPolicy requestObjectPolicy;

    public ServerMetadataCustomizer(AuthorizationServerSettings settings, DemoProperties properties,
                                    RequestObjectPolicy requestObjectPolicy) {
        this.settings = settings;
        this.properties = properties;
        this.requestObjectPolicy = requestObjectPolicy;
    }

    /** RFC 8414, {@code /.well-known/oauth-authorization-server}. */
    public void customize(OAuth2AuthorizationServerMetadata.Builder metadata) {
        apply(metadata::claim, metadata::grantTypes, metadata::scopes);
    }

    /**
     * OpenID Connect Discovery, {@code /.well-known/openid-configuration}. The same additions, to
     * the same server: two documents describing one thing that disagree are worse than one document.
     */
    public void customize(OidcProviderConfiguration.Builder configuration) {
        apply(configuration::claim, configuration::grantTypes, configuration::scopes);
    }

    /**
     * What Spring Authorization Server cannot know to advertise, because this application added it:
     * the grant it does not implement, the details types the demo validates, and the response
     * parameter a handler here supplies. The scopes come from the registered clients rather than a
     * list kept alongside them.
     */
    private void apply(BiConsumer<String, Object> claim,
                       Consumer<Consumer<List<String>>> grantTypes,
                       Consumer<Consumer<List<String>>> scopes) {
        claim.accept(IssuerIdentifierResponseHandler.ISS_PARAMETER_SUPPORTED, true);
        // OpenID Connect Session Management section 3.3: required of a server that supports it,
        // and this one does - the endpoint is served and the responses carry session_state.
        claim.accept(CHECK_SESSION_IFRAME, properties.issuerUri() + CheckSessionIframeController.URI);
        // RFC 8414 section 2 defines registration_endpoint and Spring Authorization Server puts it
        // in the OpenID document only, which is the drift this class exists to prevent.
        claim.accept("registration_endpoint",
                properties.issuerUri() + settings.getOidcClientRegistrationEndpoint());
        // An ArrayList, because these documents are cached and serialised like any other claims.
        claim.accept(AUTHORIZATION_DETAILS_TYPES_SUPPORTED,
                new ArrayList<>(RichAuthorizationDetail.SUPPORTED_TYPES));
        // RFC 9101 sections 4 and 10.5. Spring Authorization Server advertises neither, having no
        // notion of the request parameter at all; a client that cannot discover which algorithms are
        // accepted has to find out by being refused.
        claim.accept(REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED, new ArrayList<>(
                JwtSecuredAuthorizationRequestFilter.SUPPORTED_SIGNING_ALGS.stream().sorted().toList()));
        claim.accept(REQUIRE_SIGNED_REQUEST_OBJECT_METADATA,
                this.requestObjectPolicy.requireSignedRequestObject());
        // The lists are edited rather than appended to: the OIDC document already declares openid,
        // and a document that names a value twice is describing itself carelessly.
        grantTypes.accept(values ->
                addMissing(values, List.of(CibaAuthenticationToken.CIBA_GRANT_TYPE.getValue())));
        scopes.accept(values -> addMissing(values, supportedScopes()));
    }

    private static void addMissing(List<String> values, Collection<String> candidates) {
        candidates.stream().filter(candidate -> !values.contains(candidate)).forEach(values::add);
    }

    /** RFC 8414 section 2: RECOMMENDED, and absent until something works it out. */
    private Set<String> supportedScopes() {
        Set<String> scopes = new LinkedHashSet<>();
        for (DemoProperties.Client client : List.of(properties.client(), properties.confidentialClient(),
                properties.assertionClient(), properties.mtlsClient(), properties.exchangeClient(),
                properties.cibaClient(), properties.fapiClient(), properties.codeBindingClient(),
                properties.mixUpClient())) {
            scopes.addAll(client.scopes());
        }
        return scopes;
    }
}
