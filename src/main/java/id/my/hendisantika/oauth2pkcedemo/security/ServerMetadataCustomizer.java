package id.my.hendisantika.oauth2pkcedemo.security;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
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

    /** RFC 9396 section 10: the authorization_details types a client may ask for. */
    public static final String AUTHORIZATION_DETAILS_TYPES_SUPPORTED =
            "authorization_details_types_supported";

    private final AuthorizationServerSettings settings;
    private final DemoProperties properties;

    public ServerMetadataCustomizer(AuthorizationServerSettings settings, DemoProperties properties) {
        this.settings = settings;
        this.properties = properties;
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
        // RFC 8414 section 2 defines registration_endpoint and Spring Authorization Server puts it
        // in the OpenID document only, which is the drift this class exists to prevent.
        claim.accept("registration_endpoint",
                properties.issuerUri() + settings.getOidcClientRegistrationEndpoint());
        // An ArrayList, because these documents are cached and serialised like any other claims.
        claim.accept(AUTHORIZATION_DETAILS_TYPES_SUPPORTED,
                new ArrayList<>(RichAuthorizationDetail.SUPPORTED_TYPES));
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
