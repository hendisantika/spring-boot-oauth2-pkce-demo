package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.DiscoveryAttempt;
import id.my.hendisantika.oauth2pkcedemo.security.MetadataComparison;
import id.my.hendisantika.oauth2pkcedemo.security.MetadataEntry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.12
 */
@Slf4j
@Service
public class AuthorizationServerMetadataService {

    /** RFC 8414 section 3: the default well-known suffix for an OAuth authorization server. */
    public static final String OAUTH_SUFFIX = "oauth-authorization-server";

    /** OpenID Connect Discovery 1.0 section 4, and a second name for much the same document. */
    public static final String OIDC_SUFFIX = "openid-configuration";

    /** An issuer this server does not answer for, for the check in section 3.3 to catch. */
    public static final String FOREIGN_ISSUER = "https://accounts.example.com";

    /** What RFC 8414 section 2 says about each field it defines. */
    private static final Map<String, String> REQUIREMENT = Map.ofEntries(
            Map.entry("issuer", "REQUIRED"),
            Map.entry("authorization_endpoint", "REQUIRED"),
            Map.entry("token_endpoint", "REQUIRED"),
            Map.entry("response_types_supported", "REQUIRED"),
            Map.entry("scopes_supported", "RECOMMENDED"),
            Map.entry("jwks_uri", "OPTIONAL"),
            Map.entry("registration_endpoint", "OPTIONAL"),
            Map.entry("response_modes_supported", "OPTIONAL"),
            Map.entry("grant_types_supported", "OPTIONAL"),
            Map.entry("token_endpoint_auth_methods_supported", "OPTIONAL"),
            Map.entry("token_endpoint_auth_signing_alg_values_supported", "OPTIONAL"),
            Map.entry("revocation_endpoint", "OPTIONAL"),
            Map.entry("revocation_endpoint_auth_methods_supported", "OPTIONAL"),
            Map.entry("introspection_endpoint", "OPTIONAL"),
            Map.entry("introspection_endpoint_auth_methods_supported", "OPTIONAL"),
            Map.entry("code_challenge_methods_supported", "OPTIONAL"));

    /** The document is assembled from a decade of specifications, each registering its own fields. */
    private static final Map<String, String> DEFINED_BY = Map.ofEntries(
            Map.entry("device_authorization_endpoint", "RFC 8628 §4"),
            Map.entry("pushed_authorization_request_endpoint", "RFC 9126 §5"),
            Map.entry("dpop_signing_alg_values_supported", "RFC 9449 §5.1"),
            Map.entry("tls_client_certificate_bound_access_tokens", "RFC 8705 §3.3"),
            Map.entry("authorization_response_iss_parameter_supported", "RFC 9207 §3"),
            Map.entry("authorization_details_types_supported", "RFC 9396 §10"),
            Map.entry("request_object_signing_alg_values_supported", "RFC 9101 §4"),
            Map.entry("require_signed_request_object", "RFC 9101 §10.5"),
            Map.entry("require_pushed_authorization_requests", "RFC 9126 §5"),
            Map.entry("userinfo_endpoint", "OpenID Connect Discovery"),
            Map.entry("subject_types_supported", "OpenID Connect Discovery"),
            Map.entry("id_token_signing_alg_values_supported", "OpenID Connect Discovery"),
            Map.entry("end_session_endpoint", "OpenID Connect RP-Initiated Logout"));

    private final RestClient restClient;
    private final DemoProperties properties;

    public AuthorizationServerMetadataService(DemoProperties properties) {
        this.properties = properties;
        this.restClient = RestClient.create();
    }

    /**
     * RFC 8414 section 3. The well-known string goes <em>between the host and the path</em>, not on
     * the end - so an issuer with a path component publishes at a URL that reads back to front
     * compared with the OpenID Connect rule below. Getting this wrong is a 404 against a server that
     * is working perfectly.
     */
    public static String wellKnownUri(String issuer, String suffix) {
        String trimmed = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        int pathStart = trimmed.indexOf('/', trimmed.indexOf("//") + 2);
        if (pathStart < 0) {
            return trimmed + "/.well-known/" + suffix;
        }
        return trimmed.substring(0, pathStart) + "/.well-known/" + suffix + trimmed.substring(pathStart);
    }

    /**
     * OpenID Connect Discovery 1.0 section 4, which appends instead. For an issuer with no path the
     * two rules agree, which is why the difference goes unnoticed until a multi-tenant deployment.
     */
    public static String openIdConnectUri(String issuer, String suffix) {
        String trimmed = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        return trimmed + "/.well-known/" + suffix;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> fetch(String uri) {
        try {
            Map<String, Object> document = restClient.get().uri(uri).retrieve().body(Map.class);
            // Null covers the case that looks like success and is not: a redirect to a login page,
            // which is what any URL this server does not recognise gets.
            return document == null ? Map.of() : document;
        } catch (Exception ex) {
            log.debug("Could not read metadata from {}: {}", uri, ex.getMessage());
            return Map.of();
        }
    }

    /** The published document, each field labelled with where it comes from and what it is worth. */
    public List<MetadataEntry> describe(Map<String, Object> document, Map<String, Object> otherDocument) {
        List<MetadataEntry> entries = new ArrayList<>();
        new TreeSet<>(document.keySet()).forEach(name -> entries.add(new MetadataEntry(
                name,
                render(document.get(name)),
                REQUIREMENT.getOrDefault(name, DEFINED_BY.containsKey(name) ? "-" : "OPTIONAL"),
                DEFINED_BY.getOrDefault(name, "RFC 8414 §2"),
                otherDocument.containsKey(name))));
        return entries;
    }

    public MetadataComparison compare(Map<String, Object> oauthDocument, Map<String, Object> oidcDocument) {
        List<String> onlyInOauth = new ArrayList<>(new TreeSet<>(oauthDocument.keySet()));
        onlyInOauth.removeAll(oidcDocument.keySet());
        List<String> onlyInOidc = new ArrayList<>(new TreeSet<>(oidcDocument.keySet()));
        onlyInOidc.removeAll(oauthDocument.keySet());

        List<String> disagreeing = new ArrayList<>();
        new TreeSet<>(oauthDocument.keySet()).stream()
                .filter(oidcDocument::containsKey)
                .filter(name -> !render(oauthDocument.get(name)).equals(render(oidcDocument.get(name))))
                .forEach(disagreeing::add);

        return new MetadataComparison(oauthDocument.size(), oidcDocument.size(),
                onlyInOauth, onlyInOidc, disagreeing);
    }

    /**
     * What a client does before it trusts any of this. RFC 8414 section 3.3: the {@code issuer} in
     * the document must be identical to the issuer identifier the URL was built from, or the
     * response must not be used - the same reasoning as the {@code iss} parameter, one step earlier.
     */
    public List<DiscoveryAttempt> discover() {
        String uri = wellKnownUri(properties.issuerUri(), OAUTH_SUFFIX);
        List<DiscoveryAttempt> attempts = new ArrayList<>();
        attempts.add(attempt("The issuer this client was configured with",
                "Build the URL from the issuer, fetch it, compare what comes back.",
                properties.issuerUri(), uri));
        attempts.add(attempt("A client configured for somewhere else",
                "Same document, same fetch - but this client was told its authorization server is "
                        + FOREIGN_ISSUER, FOREIGN_ISSUER, uri));
        return attempts;
    }

    /**
     * RFC 8414 section 3.3, in full: "The issuer value returned MUST be identical to the
     * authorization server's issuer identifier value into which the well-known URI string was
     * inserted to create the URL used to retrieve the metadata. If these values are not identical,
     * the data contained in the response MUST NOT be used."
     */
    public static boolean issuerMatches(Map<String, Object> document, String expectedIssuer) {
        Object issuer = document.get("issuer");
        return issuer != null && expectedIssuer.equals(String.valueOf(issuer));
    }

    private DiscoveryAttempt attempt(String label, String description, String expectedIssuer,
                                     String uri) {
        Map<String, Object> document = fetch(uri);
        if (document.isEmpty()) {
            return new DiscoveryAttempt(label, description, expectedIssuer, uri, null, false,
                    "Nothing usable is published there.");
        }

        String documentIssuer = String.valueOf(document.get("issuer"));
        if (!issuerMatches(document, expectedIssuer)) {
            return new DiscoveryAttempt(label, description, expectedIssuer, uri, documentIssuer, false,
                    "The document names a different issuer, so RFC 8414 section 3.3 says none of it "
                            + "may be used.");
        }
        return new DiscoveryAttempt(label, description, expectedIssuer, uri, documentIssuer, true,
                "Accepted. The endpoints below were read from it rather than configured.");
    }

    /** The endpoints a client would take from an accepted document. */
    public Map<String, String> configuredFrom(Map<String, Object> document) {
        Map<String, String> endpoints = new LinkedHashMap<>();
        for (String name : List.of("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
                "userinfo_endpoint", "revocation_endpoint", "introspection_endpoint")) {
            if (document.containsKey(name)) {
                endpoints.put(name, render(document.get(name)));
            }
        }
        return endpoints;
    }

    private static String render(Object value) {
        if (value instanceof List<?> list) {
            return String.join(", ", list.stream().map(String::valueOf).toList());
        }
        return String.valueOf(value);
    }
}
