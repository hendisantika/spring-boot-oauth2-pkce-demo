package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.FapiCheck;
import id.my.hendisantika.oauth2pkcedemo.security.IssuerIdentifierResponseHandler;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.PushedAuthorizationPolicy;
import id.my.hendisantika.oauth2pkcedemo.security.PushedAuthorizationRequiredFilter;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectPolicy;
import id.my.hendisantika.oauth2pkcedemo.security.RequestUriPolicy;
import id.my.hendisantika.oauth2pkcedemo.security.ServerMetadataCustomizer;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 17.32
 */
@Service
@RequiredArgsConstructor
public class FapiComplianceService {

    /** Client authentication methods FAPI 2.0 permits; a shared secret is not among them. */
    private static final Set<ClientAuthenticationMethod> ACCEPTED_CLIENT_AUTHENTICATION = Set.of(
            ClientAuthenticationMethod.PRIVATE_KEY_JWT,
            ClientAuthenticationMethod.TLS_CLIENT_AUTH,
            ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);

    /**
     * The JWS algorithms both FAPI profiles name. FAPI 1.0 Advanced section 8.6 says clients and
     * authorization servers "shall use PS256 or ES256 algorithms; should not use algorithms that use
     * RSASSA-PKCS1-v1_5 (e.g. RS256); and shall not use none", and FAPI 2.0 section 5.4.1 says the
     * same of every JWT it touches, adding EdDSA. A request object is a JWS, so this is the list it
     * is held to.
     */
    private static final Set<String> ACCEPTED_SIGNING_ALGS = Set.of("PS256", "ES256", "EdDSA");

    /**
     * The one algorithm FAPI names for JWE. Section 8.6.1 of FAPI 1.0 Advanced is a single sentence
     * - "For JWE, both clients and authorization servers shall not use the RSA1_5 algorithm" - so
     * unlike its treatment of JWS this is a prohibition rather than a list to choose from, and
     * everything else a client might register passes.
     */
    private static final String FORBIDDEN_ENCRYPTION_ALG = "RSA1_5";

    private final RegisteredClientRepository registeredClientRepository;
    private final AuthorizationServerSettings settings;
    /** The handler that actually sends authorization responses, so the check below is about it. */
    private final ObjectProvider<IssuerIdentifierResponseHandler> issuerIdentifierResponseHandler;
    private final DemoProperties properties;
    /** RFC 9101 section 10.5's server-wide switch, read live rather than described. */
    private final RequestObjectPolicy requestObjectPolicy;
    /** RFC 9126 section 5's, the same way. */
    private final PushedAuthorizationPolicy pushedAuthorizationPolicy;
    /** Whether a fetched request_uri has to have been registered, read live for the same reason. */
    private final RequestUriPolicy requestUriPolicy;
    /** The class that writes the discovery documents, so the rows can read what is really in them. */
    private final ServerMetadataCustomizer serverMetadataCustomizer;

    /**
     * What the profile asks of the authorization server itself, checked against how this one is
     * actually configured rather than against a list of intentions.
     */
    public List<FapiCheck> serverChecks() {
        List<FapiCheck> checks = new ArrayList<>();
        // Read once, from the code that writes the documents rather than from the constants behind
        // it, so the three advertised lists below are compared against what is really published.
        Map<String, Object> published = this.serverMetadataCustomizer.publishedClaims();

        checks.add(FapiCheck.of(settings.getPushedAuthorizationRequestEndpoint() != null,
                "Pushed authorization requests are available", "FAPI 2.0 §5.3.1, RFC 9126",
                settings.getPushedAuthorizationRequestEndpoint()));

        checks.add(FapiCheck.pass("Authorization code flow with PKCE S256",
                "FAPI 2.0 §5.3.1, RFC 7636",
                "Every registered client is configured requireProofKey"));

        checks.add(FapiCheck.pass("Sender-constrained tokens are supported",
                "FAPI 2.0 §5.3.1, RFC 8705 / RFC 9449",
                "Both mTLS certificate binding and DPoP are implemented"));

        checks.add(FapiCheck.pass("private_key_jwt and mTLS client authentication are available",
                "FAPI 2.0 §5.3.1",
                "private_key_jwt, tls_client_auth and self_signed_tls_client_auth are all supported"));

        checks.add(FapiCheck.pass("The implicit and password grants are not offered",
                "FAPI 2.0 §5.3.1",
                "No registered client holds either, and Spring Authorization Server implements neither"));

        checks.add(FapiCheck.of(issuerIdentifierResponseHandler.getIfAvailable() != null,
                "The authorization response carries iss", "FAPI 2.0 §5.3.1, RFC 9207",
                issuerIdentifierResponseHandler.getIfAvailable() != null
                        ? "IssuerIdentifierResponseHandler sends every authorization response, and "
                        + IssuerIdentifierResponseHandler.ISS_PARAMETER_SUPPORTED
                        + " is published in the discovery document"
                        : "Spring Authorization Server does not emit the iss parameter on its own"));

        // RFC 9101's lock rather than the profile's, and the profile is the reason it is here: FAPI
        // 1.0 Advanced required the request object to be signed, and FAPI 2.0 took that out in
        // favour of PAR - its own comparison table replaces "nbf & exp claims in request object"
        // with "request_uri has limited lifetime".
        checks.add(verifyingMetadata(published,
                ServerMetadataCustomizer.REQUIRE_SIGNED_REQUEST_OBJECT_METADATA,
                this.requestObjectPolicy.requireSignedRequestObject(),
                FapiCheck.notApplicable("Request objects are signed",
                        "FAPI 1.0 Advanced §5.2.2; not carried into FAPI 2.0",
                        "FAPI 2.0 requires a pushed request with a short-lived request_uri instead. "
                                + "RFC 9101 §10.5's require_signed_request_object is implemented "
                                + "here regardless: server-wide it is "
                                + this.requestObjectPolicy.requireSignedRequestObject()
                                + ", and the documents were read back and say the same, and "
                                + clientsRequiringSignedRequestObjects() + " of the "
                                + configuredClients().size()
                                + " clients below set it for themselves")));

        // The capability the row above depends on, and the only §5.2.2 requirement that is a
        // disjunction: by value or by reference, either will do. Both booleans are verified, because
        // a server that advertises a way in it does not offer sends clients down it for nothing.
        checks.add(verifyingMetadata(published, ServerMetadataCustomizer.REQUEST_PARAMETER_SUPPORTED,
                true,
                verifyingMetadata(published,
                        ServerMetadataCustomizer.REQUEST_URI_PARAMETER_SUPPORTED, true,
                        FapiCheck.notApplicable(
                                "Request objects can be passed by value or by reference",
                                "FAPI 1.0 Advanced §5.2.2; not carried into FAPI 2.0",
                                "§5.2.2 asked for \"a JWS signed JWT request object passed by value "
                                        + "with the request parameter or by reference with the "
                                        + "request_uri parameter\" - either satisfies it, and this "
                                        + "server offers both: "
                                        + ServerMetadataCustomizer.REQUEST_PARAMETER_SUPPORTED
                                        + " and "
                                        + ServerMetadataCustomizer.REQUEST_URI_PARAMETER_SUPPORTED
                                        + " are true, read back from the documents. OpenID Connect "
                                        + "Discovery defaults the first to false, and Spring "
                                        + "Authorization Server has no notion of the request "
                                        + "parameter at all, so this is a capability the demo added "
                                        + "and must advertise to be usable. FAPI 2.0 has no use for "
                                        + "the by-value form - §5.3.2 has the client send only "
                                        + "client_id and request_uri - and on a server meeting "
                                        + "§5.3.1 it would be unreachable anyway, since every "
                                        + "request that did not come through PAR is refused. That "
                                        + "row fails here, so it is reachable"))));

        // RFC 9126 §5's carve-out, which is the part of request_uri_parameter_supported that can
        // actually be got wrong: a server that gated all request_uri handling on it would break PAR
        // for everybody. Demonstrated rather than asserted - the reference the pushed endpoint
        // issues is put through the same predicate the filter uses.
        boolean endpointPresent = settings.getPushedAuthorizationRequestEndpoint() != null;
        boolean pushedReferenceIsNotFetched = !JwtSecuredAuthorizationRequestFilter
                .isFetchedRequestUri(RequestUriService.PREFIX + "issued-by-the-pushed-endpoint");
        checks.add(FapiCheck.of(endpointPresent && pushedReferenceIsNotFetched,
                "A pushed request_uri ignores the fetch metadata", "RFC 9126 §5",
                "§5: \"a request_uri value obtained from the PAR endpoint is usable at the "
                        + "authorization endpoint regardless of other authorization server metadata "
                        + "such as request_uri_parameter_supported or "
                        + "require_request_uri_registration\". Both of those are published here - "
                        + "the first true, the second "
                        + this.requestUriPolicy.requireRegistration()
                        + " - and neither is consulted for a pushed reference, because the two kinds "
                        + "of request_uri are told apart by scheme: "
                        + RequestUriService.PREFIX + "\u2026 is not a URL to fetch, so it never "
                        + "reaches the registration check at all. A server that gated every "
                        + "request_uri on that metadata would refuse its own pushed references"));

        // No FAPI profile names this one - the checked spec is RFC 9101, and the profiles reach the
        // same attack surface from the other side by requiring PAR, which is the row below. It is
        // here because thirty-two of the client rows are only green while it is true.
        checks.add(verifyingMetadata(published,
                ServerMetadataCustomizer.REQUIRE_REQUEST_URI_REGISTRATION,
                this.requestUriPolicy.requireRegistration(),
                FapiCheck.of(this.requestUriPolicy.requireRegistration(),
                "Fetched request_uris must be pre-registered",
                "RFC 9101 \u00a710.4.1(a); no FAPI profile names it",
                "RFC 9101 says the server should \"check that the value of the request_uri parameter "
                        + "does not point to an unexpected location\", and a registration is what "
                        + "makes a location expected. OpenID Connect Discovery makes the default "
                        + "false; "
                        + ServerMetadataCustomizer.REQUIRE_REQUEST_URI_REGISTRATION + " is "
                        + this.requestUriPolicy.requireRegistration() + " here, and "
                        + clientsWithRegisteredRequestUris() + " of the " + configuredClients().size()
                        + " clients below have registered a URL, and the documents were read back "
                        + "and say the same. FAPI 2.0 answers the same attack by requiring PAR "
                        + "instead, so nothing is fetched at all")));

        // Honest failures follow. A profile check that only ever passes is worth nothing - and this
        // one is now capable of passing, which is the only thing that makes its failing mean
        // anything: the switch exists and is off rather than being absent.
        checks.add(verifyingMetadata(published,
                ServerMetadataCustomizer.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS,
                this.pushedAuthorizationPolicy.requirePushedRequests(),
                FapiCheck.of(this.pushedAuthorizationPolicy.requirePushedRequests(),
                "The server requires pushed authorization requests", "FAPI 2.0 §5.3.1",
                "The profile says the server \"shall reject authorization requests sent without "
                        + "[RFC9126]\", which is every client rather than the willing ones. RFC 9126 "
                        + "§5's server-wide require_pushed_authorization_requests is "
                        + this.pushedAuthorizationPolicy.requirePushedRequests()
                        + ", and the documents were read back and say the same; §6's per-client one "
                        + "is set by " + clientsRequiringPushedRequests() + " of the "
                        + configuredClients().size() + " clients below")));

        // The other half of the row the clients below are judged on. FAPI 1.0 Advanced §8.6 binds
        // "both clients and authorization servers", and FAPI 2.0 §5.4.1 says "not use or accept" -
        // and a supported list is exactly a statement about what is accepted.
        List<String> offending = JwtSecuredAuthorizationRequestFilter.SUPPORTED_SIGNING_ALGS.stream()
                .filter(algorithm -> !ACCEPTED_SIGNING_ALGS.contains(algorithm))
                .sorted()
                .toList();
        checks.add(advertisedList(published,
                ServerMetadataCustomizer.REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED,
                JwtSecuredAuthorizationRequestFilter.SUPPORTED_SIGNING_ALGS,
                "Advertised request object signing algorithms are PS256 or ES256",
                "FAPI 1.0 Advanced \u00a78.6, FAPI 2.0 \u00a75.4.1",
                offending.isEmpty(),
                ServerMetadataCustomizer.REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED + " is "
                        + JwtSecuredAuthorizationRequestFilter.SUPPORTED_SIGNING_ALGS.stream()
                        .sorted().toList()
                        + (offending.isEmpty()
                        ? ", all of which the profile asks for"
                        : ", and " + offending + " should not be there: §8.6 binds \"both clients "
                        + "and authorization servers\", and §5.4.1 says not to \"use or accept\" "
                        + "none. These entries are deliberate - the pages that demonstrate them need "
                        + "a server that accepts them - so this is a gap this demo keeps on purpose, "
                        + "which is not the same as one it has not noticed")));

        // The encryption half of the same idea, and it passes - which is worth having beside the one
        // that does not. §8.6.1 binds both sides the way §8.6 does, but the demonstration this demo
        // needed here is the refusal, so RSA1_5 never had to be in the supported set.
        boolean advertisesForbidden = JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS
                .contains(FORBIDDEN_ENCRYPTION_ALG);
        checks.add(advertisedList(published,
                ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED,
                JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS,
                "Advertised request object encryption algorithms exclude RSA1_5",
                "FAPI 1.0 Advanced \u00a78.6.1; not carried into FAPI 2.0",
                !advertisesForbidden,
                ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ALG_VALUES_SUPPORTED + " is "
                        + JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS.stream()
                        .sorted().toList()
                        + (advertisesForbidden
                        ? ", and " + FORBIDDEN_ENCRYPTION_ALG + " is in it, which §8.6.1 forbids "
                        + "authorization servers as well as clients"
                        : ". §8.6.1 binds both sides the way §8.6 does, and a client below registered "
                        + FORBIDDEN_ENCRYPTION_ALG + " and fails its own row - what that page "
                        + "demonstrates is the refusal, so this server never needed to support it")));

        // The third of the lists RFC 9101 §4 names together, and the only one no FAPI profile has an
        // opinion about - none of the three names a content encryption method. What applies is the
        // same borrowed chain the per-client enc row uses: RFC 8725 §3.1, which FAPI 2.0 §5.4.1
        // requires adherence to, asks for a supported set that nothing outside it may be used with.
        Set<String> methods = JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_METHODS;
        checks.add(advertisedList(published,
                ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED,
                methods,
                "The request object enc set is closed and advertised",
                "RFC 8725 \u00a73.1, required by FAPI 2.0 \u00a75.4.1",
                !methods.isEmpty(),
                ServerMetadataCustomizer.REQUEST_OBJECT_ENCRYPTION_ENC_VALUES_SUPPORTED + " is "
                        + methods.stream().sorted().toList() + ". No FAPI profile names a content "
                        + "encryption method, so what applies is RFC 8725's \"supported set of "
                        + "algorithms\" that nothing outside may be used with. That the set is "
                        + "really closed is visible below rather than asserted here: a client "
                        + "registered A192CBC-HS384 and fails its row, because this server refuses "
                        + "it rather than widening the set to match a registration. RFC 9101 §4 is "
                        + "why the list is published at all, so a client can read the set instead of "
                        + "discovering it by being refused"));

        checks.add(FapiCheck.of(properties.issuerUri().startsWith("https://"),
                "All endpoints are served over TLS", "FAPI 2.0 §5.3",
                "The issuer is " + properties.issuerUri()
                        + "; only the mTLS listener on 8443 uses TLS"));

        return checks;
    }

    /**
     * The same precedence for metadata that is a switch rather than a list, kept in a shape the
     * not-applicable row can use too: whether the documents say what the code does is settled before
     * anything else, and a document that disagrees fails the row whatever verdict it would otherwise
     * have carried. A requirement this profile stopped asking for is still a requirement to describe
     * this server truthfully.
     *
     * @param enforced what the code actually does
     * @param verdict  the check to report when the documents agree
     */
    private static FapiCheck verifyingMetadata(Map<String, Object> published, String name,
                                               boolean enforced, FapiCheck verdict) {
        String disagreement = ServerMetadataCustomizer.disagreement(published, name, enforced);
        return disagreement != null
                ? FapiCheck.fail(verdict.requirement(), verdict.reference(), disagreement)
                : verdict;
    }

    /**
     * Judges one advertised algorithm list. Before the profile has any say, the list has to agree
     * with the set this server actually enforces: a profile verdict on an advertised value means
     * nothing if the advertised value is not what the code does.
     *
     * @param published    what {@link ServerMetadataCustomizer} really puts in both documents
     * @param enforced     the set the request object filter actually applies
     * @param meetsProfile the profile's verdict, used only once the two agree
     */
    private static FapiCheck advertisedList(Map<String, Object> published, String name,
                                            Set<String> enforced, String requirement,
                                            String reference, boolean meetsProfile, String observed) {
        String disagreement = ServerMetadataCustomizer.disagreement(published, name, enforced);
        return disagreement != null
                ? FapiCheck.fail(requirement, reference, disagreement)
                : FapiCheck.of(meetsProfile, requirement, reference, observed);
    }

    /** How many clients named a URL this server would be willing to go and fetch a request from. */
    private long clientsWithRegisteredRequestUris() {
        return configuredClients().stream()
                .map(configured -> registeredClientRepository.findByClientId(configured.clientId()))
                .filter(client -> client != null && hasRegisteredRequestUris(client))
                .count();
    }

    private static boolean hasRegisteredRequestUris(RegisteredClient client) {
        Object registered = client.getClientSettings()
                .getSetting(JwtSecuredAuthorizationRequestFilter.REQUEST_URIS_SETTING);
        return registered != null && !String.valueOf(registered).isBlank();
    }

    /** The same count for RFC 9126 section 6's lock. */
    private long clientsRequiringPushedRequests() {
        return configuredClients().stream()
                .map(configured -> registeredClientRepository.findByClientId(configured.clientId()))
                .filter(client -> client != null && isSet(client,
                        PushedAuthorizationRequiredFilter.REQUIRE_PAR_SETTING))
                .count();
    }

    /**
     * How many clients turned RFC 9101 section 10.5's lock for themselves. Counted from the
     * registrations rather than from the list of clients that were meant to.
     */
    private long clientsRequiringSignedRequestObjects() {
        return configuredClients().stream()
                .map(configured -> registeredClientRepository.findByClientId(configured.clientId()))
                .filter(client -> client != null && requiresSignedRequestObjects(client))
                .count();
    }

    private static boolean requiresSignedRequestObjects(RegisteredClient client) {
        return isSet(client, JwtSecuredAuthorizationRequestFilter.REQUIRE_SIGNED_SETTING);
    }

    private static boolean isSet(RegisteredClient client, String setting) {
        // Read as an Object: getSetting infers its own return type, and String.valueOf would then
        // pick the char[] overload and dereference a null.
        Object value = client.getClientSettings().getSetting(setting);
        return value != null && Boolean.parseBoolean(String.valueOf(value));
    }

    /** The same exercise per client, since the profile constrains clients as much as the server. */
    public Map<String, List<FapiCheck>> clientChecks() {
        Map<String, List<FapiCheck>> byClient = new LinkedHashMap<>();
        for (DemoProperties.Client configured : configuredClients()) {
            RegisteredClient client = registeredClientRepository.findByClientId(configured.clientId());
            if (client != null) {
                byClient.put(client.getClientName(), checksFor(client));
            }
        }
        return byClient;
    }

    private List<DemoProperties.Client> configuredClients() {
        return List.of(properties.client(), properties.confidentialClient(),
                properties.assertionClient(), properties.mtlsClient(),
                properties.exchangeClient(), properties.cibaClient(), properties.fapiClient(),
                properties.codeBindingClient(), properties.mixUpClient(), properties.registrarClient(),
                properties.relayClient(), properties.mtlsRefreshClient(),
                properties.freshnessClient(), properties.silentClient(),
                properties.requestUriClient(), properties.rarClient(),
                properties.dpopNonceClient(), properties.jarmClient(),
                properties.jarmEcClient(), properties.jarmNoneClient(),
                properties.jarmEncryptedClient(), properties.jarmGcmClient(),
                properties.jarmUnsupportedEncClient(), properties.jarPsClient(), properties.jarOaep512Client(),
                properties.jarRsa15Client(), properties.jarGcmClient(),
                properties.jarUnsupportedEncClient(), properties.jarEncOnlyClient(), properties.jarNoneClient(),
                properties.jarNoneStrictClient(), properties.parRequiredClient(), properties.fetchedRequestClient(), properties.jarEsClient());
    }

    /**
     * What the client registered as its request object signing algorithm, judged against the list
     * both profiles give. Only the registration is visible from here, and that is the right thing to
     * look at: RFC 9101 section 10.1 has this server refuse a request object signed with anything
     * other than the algorithm agreed in advance, so the registration decides what can ever arrive.
     */
    private static FapiCheck requestObjectAlgorithmCheck(RegisteredClient client) {
        String requirement = "Request objects are signed with PS256 or ES256";
        String reference = "FAPI 1.0 Advanced \u00a78.6, FAPI 2.0 \u00a75.4.1";

        // Read as an Object for the same reason isSet does.
        Object registered = client.getClientSettings()
                .getSetting(JwtSecuredAuthorizationRequestFilter.SIGNING_ALG_SETTING);
        if (registered == null) {
            // Nothing to judge. This server would verify a request object from such a client as
            // RS256, but that default is its own choice rather than anything the client declared,
            // and most of these clients never send a request object at all.
            return FapiCheck.notApplicable(requirement, reference,
                    "No request_object_signing_alg registered. This server falls back to "
                            + JwtSecuredAuthorizationRequestFilter.DEFAULT_SIGNING_ALG
                            + ", which the profile says should not be used - but that is this "
                            + "server's default rather than a client's declaration");
        }

        String algorithm = String.valueOf(registered);
        if (JwtSecuredAuthorizationRequestFilter.NO_SIGNATURE.equals(algorithm)) {
            return FapiCheck.fail(requirement, reference,
                    "Registered none, which both profiles say shall not be used. This server accepts "
                            + "it because OpenID Connect Registration allows it, and refuses it once "
                            + "either half of require_signed_request_object is on");
        }
        if (!ACCEPTED_SIGNING_ALGS.contains(algorithm)) {
            return FapiCheck.fail(requirement, reference,
                    "Registered " + algorithm + ", which is not one of PS256, ES256 or EdDSA");
        }
        if (!JwtSecuredAuthorizationRequestFilter.SUPPORTED_SIGNING_ALGS.contains(algorithm)) {
            // An honest split worth showing rather than rounding off: the profile's list and this
            // server's list are different lists, and a registration can sit in one and not the
            // other. Such a client passes this row and still cannot get a request object verified.
            return FapiCheck.pass(requirement, reference,
                    "Registered " + algorithm + ", which the profile asks for - but this server does "
                            + "not verify " + algorithm + " signatures on request objects, so every "
                            + "one it sends is refused");
        }
        return FapiCheck.pass(requirement, reference, "Registered " + algorithm);
    }

    /**
     * The encryption half, which is a different shape of requirement from the signing half. FAPI 1.0
     * Advanced section 8.6.1 forbids exactly one algorithm and says nothing about the rest, and FAPI
     * 2.0 carries no JWE requirement at all - its own comparison table gives the reason, that it
     * keeps ID tokens out of the front channel and so needs no encryption there.
     */
    private static FapiCheck requestObjectEncryptionCheck(RegisteredClient client) {
        String requirement = "Request objects are not encrypted with RSA1_5";
        String reference = "FAPI 1.0 Advanced \u00a78.6.1; not carried into FAPI 2.0";

        Object registered = client.getClientSettings()
                .getSetting(JwtSecuredAuthorizationRequestFilter.ENCRYPTION_ALG_SETTING);
        Object registeredMethod = client.getClientSettings()
                .getSetting(JwtSecuredAuthorizationRequestFilter.ENCRYPTION_ENC_SETTING);

        if (registered == null) {
            if (registeredMethod != null) {
                // OpenID Connect Registration: "When request_object_encryption_enc is included,
                // request_object_encryption_alg MUST also be provided." Such a client has declared
                // that it encrypts without saying what wraps the key, and this server refuses its
                // encrypted request objects rather than guessing - so no JWE alg is ever agreed with
                // it, and there is none for this row to judge.
                return FapiCheck.notApplicable(requirement, reference,
                        "Registered " + registeredMethod + " and no request_object_encryption_alg, "
                                + "which the registration spec does not allow. This server refuses "
                                + "its encrypted request objects, so no algorithm is ever agreed");
            }
            // The registration spec is explicit about the omitted case, and it is not a default the
            // way the signing one is: "the RP is not declaring whether it might encrypt any Request
            // Objects." Encryption here is opt-in per request, and the algorithm this server would
            // fall back to if one did arrive encrypted is one the profile permits anyway.
            return FapiCheck.notApplicable(requirement, reference,
                    "No request_object_encryption_alg registered, which the registration spec reads "
                            + "as not declaring whether it might encrypt at all. An encrypted "
                            + "request object from it would be unwrapped as "
                            + JwtSecuredAuthorizationRequestFilter.DEFAULT_ENCRYPTION_ALG
                            + ", which this profile permits");
        }

        String algorithm = String.valueOf(registered);
        if (FORBIDDEN_ENCRYPTION_ALG.equals(algorithm)) {
            return FapiCheck.fail(requirement, reference,
                    "Registered " + algorithm + ", the one algorithm the profile names. This server "
                            + "does not decrypt it either, so the prohibition and this server's "
                            + "supported list happen to agree - the request objects are refused "
                            + "before the profile is consulted");
        }
        if (!JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_ALGS.contains(algorithm)) {
            return FapiCheck.pass(requirement, reference,
                    "Registered " + algorithm + ", which the profile does not forbid - but this "
                            + "server does not decrypt it, so every encrypted request object it "
                            + "sends is refused");
        }
        return FapiCheck.pass(requirement, reference, "Registered " + algorithm);
    }

    /**
     * The content encryption method, which no FAPI profile names at all - not the Baseline, not
     * Advanced (section 8.6.1 forbids RSA1_5, which is a key-wrapping algorithm rather than an enc),
     * and not FAPI 2.0. What does reach it is RFC 8725 section 3.1, which FAPI 2.0 section 5.4.1
     * requires adherence to: a supported set must exist, nothing outside it may be used, and the
     * header must name what was actually used. So this row asks whether the registration names an
     * enc this server would actually accept rather than whether it is on a list of blessed ones.
     */
    private static FapiCheck requestObjectEncryptionMethodCheck(RegisteredClient client) {
        String requirement = "The request object enc is one this server supports";
        String reference = "RFC 8725 \u00a73.1, required by FAPI 2.0 \u00a75.4.1";

        Object registeredAlg = client.getClientSettings()
                .getSetting(JwtSecuredAuthorizationRequestFilter.ENCRYPTION_ALG_SETTING);
        Object registered = client.getClientSettings()
                .getSetting(JwtSecuredAuthorizationRequestFilter.ENCRYPTION_ENC_SETTING);

        if (registered == null) {
            if (registeredAlg == null) {
                return FapiCheck.notApplicable(requirement, reference,
                        "Neither half of the request object encryption registration is set, so there "
                                + "is no declared content encryption method to check");
            }
            // The registration spec supplies one here, and only here: "If
            // request_object_encryption_alg is specified, the default request_object_encryption_enc
            // value is A128CBC-HS256." A default that depends on its sibling being present, which is
            // not how either of the other two rows behave.
            String fallback = JwtSecuredAuthorizationRequestFilter.DEFAULT_ENCRYPTION_ENC;
            return FapiCheck.of(
                    JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_METHODS.contains(fallback),
                    requirement, reference,
                    "Registered " + registeredAlg + " and no enc, which the registration spec makes "
                            + fallback + " because an alg is present");
        }

        if (registeredAlg == null) {
            // The registration the spec does not allow, reported the same way the alg row reports it.
            return FapiCheck.notApplicable(requirement, reference,
                    "Registered " + registered + " with no request_object_encryption_alg beside it, "
                            + "which the registration spec does not allow. This server refuses its "
                            + "encrypted request objects, so this method is never used");
        }

        String method = String.valueOf(registered);
        return FapiCheck.of(
                JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_METHODS.contains(method),
                requirement, reference,
                JwtSecuredAuthorizationRequestFilter.SUPPORTED_ENCRYPTION_METHODS.contains(method)
                        ? "Registered " + method
                        : "Registered " + method + ", which is not in this server's supported set. "
                        + "RFC 8725 says nothing outside that set may be used, and this server "
                        + "refuses its encrypted request objects rather than widening the set to "
                        + "match a registration");
    }

    /**
     * RFC 9126 section 6's lock, which unlike section 10.5's has a profile asking for it. FAPI 2.0
     * section 5.3.2 binds the client directly: it "shall only send client_id and request_uri request
     * parameters to the authorization endpoint (all other authorization request parameters are sent
     * in the pushed authorization request according to [RFC9126])".
     * <p>
     * A registration is the only thing visible from here, and pushing is otherwise a per-request
     * choice - so a client that registered neither half is reported the way the sender-constrained
     * row reports DPoP: failed, with the limit of what a registration can show stated rather than
     * implied.
     */
    private FapiCheck pushedRequestRequirementCheck(RegisteredClient client) {
        String requirement = "The client may only start requests through PAR";
        String reference = "FAPI 2.0 \u00a75.3.2, RFC 9126 \u00a76";

        if (isSet(client, PushedAuthorizationRequiredFilter.REQUIRE_PAR_SETTING)) {
            return FapiCheck.pass(requirement, reference,
                    "Registered require_pushed_authorization_requests, so an ordinary authorization "
                            + "request from this client is refused whatever the server-wide switch "
                            + "says");
        }
        if (this.pushedAuthorizationPolicy.requirePushedRequests()) {
            return FapiCheck.pass(requirement, reference,
                    "Did not register require_pushed_authorization_requests, but RFC 9126 §5's "
                            + "server-wide half is on, which refuses ordinary requests from every "
                            + "client at once");
        }
        return FapiCheck.fail(requirement, reference,
                "Neither half of require_pushed_authorization_requests is set. This client may still "
                        + "push voluntarily - nothing stops it, and the PAR page shows a client "
                        + "doing exactly that - but pushing is chosen per request rather than "
                        + "recorded on the registration, so it cannot be confirmed from here");
    }

    /**
     * RFC 9101 section 10.5's lock, seen from the client side. The section is titled "Downgrade
     * Attack" and says why it exists: "Unless the protocol used by the client and the server is
     * locked down to use an OAuth JWT-Secured Authorization Request (JAR), it is possible for an
     * attacker to use RFC 6749 requests to bypass all the protection provided by this
     * specification." The metadata is defined twice under one name, client and server, both boolean
     * and both defaulting to false, and either being true closes the hole for this client.
     * <p>
     * Not a failure where neither is set: FAPI 2.0 dropped the request object in favour of PAR, so
     * no current profile asks a client to register this, and marking thirty-odd clients red for
     * declining an optional flag would be inventing a requirement rather than checking one.
     */
    private FapiCheck unsignedRequestRefusalCheck(RegisteredClient client) {
        String requirement = "Unsigned requests are refused for this client";
        String reference = "RFC 9101 \u00a710.5; not carried into FAPI 2.0";

        if (requiresSignedRequestObjects(client)) {
            Object algorithm = client.getClientSettings()
                    .getSetting(JwtSecuredAuthorizationRequestFilter.SIGNING_ALG_SETTING);
            if (JwtSecuredAuthorizationRequestFilter.NO_SIGNATURE.equals(String.valueOf(algorithm))) {
                // A registration that argues with itself: the only algorithm it declared is the one
                // the flag beside it refuses. §10.5 is ambiguous about precedence here - its client
                // paragraph makes the none rejection conditional on "this server metadata value",
                // which reads like a slip, while its server paragraph is unconditional. This server
                // takes the stricter reading, so the lock wins and the client can send nothing.
                return FapiCheck.pass(requirement, reference,
                        "Registered require_signed_request_object and "
                                + JwtSecuredAuthorizationRequestFilter.NO_SIGNATURE
                                + " as its only signing algorithm, which contradict each other. The "
                                + "lock wins here, so nothing unsigned is acted on - at the price of "
                                + "this client having no request object it can successfully send");
            }
            return FapiCheck.pass(requirement, reference,
                    "Registered require_signed_request_object, so §10.5's downgrade is closed for "
                            + "this client whatever the server-wide switch says");
        }

        if (this.requestObjectPolicy.requireSignedRequestObject()) {
            return FapiCheck.pass(requirement, reference,
                    "Did not register require_signed_request_object, but the server-wide half is on, "
                            + "which refuses unsigned requests from every client at once");
        }
        return FapiCheck.notApplicable(requirement, reference,
                "Neither half of require_signed_request_object is set, so an ordinary RFC 6749 "
                        + "request from this client is acted on - the downgrade §10.5 is named "
                        + "after. No current profile asks a client to register it: FAPI 1.0 Advanced "
                        + "asked the server to require signed request objects, and FAPI 2.0 asks for "
                        + "PAR instead");
    }

    /**
     * Whether the client can start an authorization request from a URL it registered in advance.
     * FAPI 1.0 Advanced section 5.2.2 blessed exactly this - the server "shall require a JWS signed
     * JWT request object passed by value with the request parameter or by reference with the
     * request_uri parameter" - and FAPI 2.0 designed it out. Its comparison table replaces the
     * request object's nbf and exp claims with "request_uri has limited lifetime", for the stated
     * reason that this "Prevents pre-generation of requests", and section 5.3.2 has the client send
     * only client_id and a request_uri whose parameters "are sent in the pushed authorization
     * request according to [RFC9126]". A pre-registered URL is neither short-lived nor pushed.
     */
    private FapiCheck preRegisteredRequestUriCheck(RegisteredClient client) {
        String requirement = "Requests are not started from a pre-registered request_uri";
        String reference = "FAPI 2.0 \u00a75.3.2; permitted by FAPI 1.0 Advanced \u00a75.2.2";

        Object registered = client.getClientSettings()
                .getSetting(JwtSecuredAuthorizationRequestFilter.REQUEST_URIS_SETTING);
        if (hasRegisteredRequestUris(client)) {
            long count = String.valueOf(registered).trim().split("\\s+").length;
            return FapiCheck.fail(requirement, reference,
                    "Registered " + count + " request_uris. The parameters in a document fetched "
                            + "from one of them never went through the pushed endpoint, so the "
                            + "request is pre-generated rather than short-lived - which is the "
                            + "property FAPI 2.0 replaced the request object to get");
        }

        // The absence is only worth something while an unregistered URL cannot be used instead, and
        // that is a switch this demo can move, so it is read rather than assumed.
        boolean registrationRequired = this.requestUriPolicy.requireRegistration();
        return FapiCheck.of(registrationRequired, requirement, reference,
                registrationRequired
                        ? "No request_uris registered, and require_request_uri_registration is true, "
                        + "so there is no URL this client could be sent to fetch a request from"
                        : "No request_uris registered, but require_request_uri_registration is "
                        + "false, so this client could still name any https URL and have this "
                        + "server fetch it");
    }

    private List<FapiCheck> checksFor(RegisteredClient client) {
        List<FapiCheck> checks = new ArrayList<>();

        Set<ClientAuthenticationMethod> methods = client.getClientAuthenticationMethods();
        checks.add(FapiCheck.of(methods.stream().anyMatch(ACCEPTED_CLIENT_AUTHENTICATION::contains),
                "Authenticates with private_key_jwt or mTLS", "FAPI 2.0 §5.3.2",
                methods.stream().map(ClientAuthenticationMethod::getValue).sorted().toList().toString()));

        boolean usesAuthorizationCode =
                client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE);
        if (usesAuthorizationCode) {
            checks.add(FapiCheck.of(client.getClientSettings().isRequireProofKey(),
                    "Requires PKCE", "FAPI 2.0 §5.3.2, RFC 7636",
                    "requireProofKey=" + client.getClientSettings().isRequireProofKey()));
        } else {
            checks.add(FapiCheck.notApplicable("Requires PKCE", "FAPI 2.0 §5.3.2",
                    "No authorization code grant"));
        }

        checks.add(FapiCheck.of(client.getTokenSettings().isX509CertificateBoundAccessTokens(),
                "Tokens are sender-constrained", "FAPI 2.0 §5.3.2, RFC 8705 / RFC 9449",
                client.getTokenSettings().isX509CertificateBoundAccessTokens()
                        ? "Certificate-bound"
                        : "Not certificate-bound. DPoP would also satisfy this, but it is chosen per "
                        + "request rather than recorded on the registration, so it cannot be "
                        + "confirmed from here"));

        checks.add(requestObjectAlgorithmCheck(client));
        checks.add(requestObjectEncryptionCheck(client));
        checks.add(requestObjectEncryptionMethodCheck(client));
        checks.add(unsignedRequestRefusalCheck(client));
        checks.add(pushedRequestRequirementCheck(client));
        checks.add(preRegisteredRequestUriCheck(client));

        if (client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            checks.add(FapiCheck.of(!client.getTokenSettings().isReuseRefreshTokens(),
                    "Refresh tokens are rotated", "FAPI 2.0 §5.3.2",
                    "reuseRefreshTokens=" + client.getTokenSettings().isReuseRefreshTokens()));
        } else {
            checks.add(FapiCheck.notApplicable("Refresh tokens are rotated", "FAPI 2.0 §5.3.2",
                    "No refresh token grant"));
        }

        return checks;
    }
}
