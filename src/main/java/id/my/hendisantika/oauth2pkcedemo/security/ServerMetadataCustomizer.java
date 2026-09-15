package id.my.hendisantika.oauth2pkcedemo.security;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.CheckSessionIframeController;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
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

    /** RFC 9101 section 4 names all three of these together; here are the other two. */
    public static final String REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED =
            "request_object_encryption_alg_values_supported";

    public static final String REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED =
            "request_object_encryption_enc_values_supported";

    /** RFC 9126 section 5, the server-wide half of the pair whose client half is implemented. */
    public static final String REQUIRE_PUSHED_AUTHORIZATION_REQUESTS =
            "require_pushed_authorization_requests";

    /** OpenID Connect Discovery section 3: the {@code request} parameter, which this server reads. */
    public static final String REQUEST_PARAMETER_SUPPORTED = "request_parameter_supported";

    /**
     * OpenID Connect Discovery section 3: the {@code request_uri} parameter, meaning a URL the
     * server fetches the request object from. This one does, from the URLs a client registered - and
     * <a href="https://www.rfc-editor.org/rfc/rfc9126#section-5">RFC 9126 section 5</a> says a
     * request_uri obtained from the pushed endpoint is usable regardless of this value either way.
     */
    public static final String REQUEST_URI_PARAMETER_SUPPORTED = "request_uri_parameter_supported";

    /** OpenID Connect Discovery section 3: which URLs may be fetched, rather than whether any may. */
    public static final String REQUIRE_REQUEST_URI_REGISTRATION = "require_request_uri_registration";

    private final AuthorizationServerSettings settings;
    private final DemoProperties properties;

    /** Read on every request rather than captured, so the published values are the live ones. */
    private final RequestObjectPolicy requestObjectPolicy;
    private final PushedAuthorizationPolicy pushedAuthorizationPolicy;
    private final RequestUriPolicy requestUriPolicy;

    public ServerMetadataCustomizer(AuthorizationServerSettings settings, DemoProperties properties,
                                    RequestObjectPolicy requestObjectPolicy,
                                    PushedAuthorizationPolicy pushedAuthorizationPolicy,
                                    RequestUriPolicy requestUriPolicy) {
        this.settings = settings;
        this.properties = properties;
        this.requestObjectPolicy = requestObjectPolicy;
        this.pushedAuthorizationPolicy = pushedAuthorizationPolicy;
        this.requestUriPolicy = requestUriPolicy;
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
     * The claims this class adds, collected through the same {@link #apply} call that writes them
     * into both documents. Reading them back is what lets a check compare what this server
     * advertises against what it actually enforces, instead of reporting one constant twice and
     * calling that agreement.
     * <p>
     * The grant type and scope callbacks are handed a consumer that does nothing: those mutate the
     * builder's own lists rather than arriving as claims, and nothing here needs them.
     */
    public Map<String, Object> publishedClaims() {
        Map<String, Object> claims = new LinkedHashMap<>();
        apply(claims::put, grantTypes -> { }, scopes -> { });
        return claims;
    }

    /**
     * Whether one advertised list says what this server actually does. A server that advertises an
     * algorithm it will not accept, or accepts one it never advertised, has told its clients
     * something untrue - and every client that read the document has planned against the wrong set.
     * <p>
     * Kept here rather than beside the checks that call it, because this class is what decides what
     * the documents say: the question "does the document match the code" belongs with the document.
     *
     * @param published the claims, as {@link #publishedClaims()} returns them
     * @param name      the metadata name to look up
     * @param enforced  the set the code actually applies
     * @return {@code null} when the two agree, or a description of how they do not
     */
    public static String disagreement(Map<String, Object> published, String name,
                                      Set<String> enforced) {
        List<String> enforcedList = enforced.stream().sorted().toList();
        Object value = published.get(name);
        if (!(value instanceof Collection<?> collection)) {
            return name + " is not in the discovery documents, so a client has no way to learn that "
                    + "this server enforces " + enforcedList + " except by being refused";
        }

        List<String> publishedList = collection.stream().map(String::valueOf).sorted().toList();
        if (!publishedList.equals(enforcedList)) {
            return name + " advertises " + publishedList + " but this server enforces " + enforcedList
                    + ". A document that disagrees with the code is worse than no document: every "
                    + "client reading it plans against the wrong set";
        }
        return null;
    }

    /**
     * The boolean counterpart of {@link #disagreement(Map, String, Set)}, for the metadata that is a
     * switch rather than a list. The same reasoning applies and one case more: a server that
     * advertises {@code true} while enforcing nothing has published a defence it does not have, and
     * a client reading that has been told it is safe when it is not.
     * <p>
     * Absence is a disagreement here too. These switches all default to false in their
     * specifications, so a client that cannot find the value is entitled to assume the lock is off -
     * which is wrong whenever it is on.
     *
     * @param published the claims, as {@link #publishedClaims()} returns them
     * @param name      the metadata name to look up
     * @param enforced  what the code actually does
     * @return {@code null} when the two agree, or a description of how they do not
     */
    public static String disagreement(Map<String, Object> published, String name, boolean enforced) {
        Object value = published.get(name);
        if (!(value instanceof Boolean advertised)) {
            return name + " is not in the discovery documents, so a client reading them is entitled "
                    + "to assume the specification default of false, while this server enforces "
                    + enforced;
        }
        if (advertised != enforced) {
            return name + " advertises " + advertised + " but this server enforces " + enforced
                    + (advertised
                    ? ". Publishing a defence that is not applied is the worse direction: a client "
                    + "reading it has been told it is protected when it is not"
                    : ". Clients are being refused for a rule the documents do not mention");
        }
        return null;
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
        // The same three metadata values RFC 9101 section 4 names together. Both of these were
        // implemented and unadvertised, which leaves a client to discover them by being refused.
        claim.accept(REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED, new ArrayList<>(
                JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS.stream().sorted().toList()));
        claim.accept(REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED, new ArrayList<>(
                JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_METHODS.stream().sorted().toList()));
        claim.accept(REQUIRE_SIGNED_REQUEST_OBJECT_METADATA,
                this.requestObjectPolicy.requireSignedRequestObject());
        // RFC 9126 section 5: "whether the authorization server accepts authorization request data
        // only via PAR", read live so the document describes the server rather than its defaults.
        claim.accept(REQUIRE_PUSHED_AUTHORIZATION_REQUESTS,
                this.pushedAuthorizationPolicy.requirePushedRequests());
        // OpenID Connect Discovery section 3. Publishing these is not decoration: omitted, they
        // default to request_parameter_supported=false and request_uri_parameter_supported=true,
        // which describes this server backwards on both counts.
        claim.accept(REQUEST_PARAMETER_SUPPORTED, true);
        claim.accept(REQUEST_URI_PARAMETER_SUPPORTED, true);
        claim.accept(REQUIRE_REQUEST_URI_REGISTRATION, this.requestUriPolicy.requireRegistration());
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
