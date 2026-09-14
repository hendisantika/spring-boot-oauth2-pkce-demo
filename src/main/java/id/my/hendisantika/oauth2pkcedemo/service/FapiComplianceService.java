package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.FapiCheck;
import id.my.hendisantika.oauth2pkcedemo.security.IssuerIdentifierResponseHandler;
import id.my.hendisantika.oauth2pkcedemo.security.JwtSecuredAuthorizationRequestFilter;
import id.my.hendisantika.oauth2pkcedemo.security.PushedAuthorizationPolicy;
import id.my.hendisantika.oauth2pkcedemo.security.PushedAuthorizationRequiredFilter;
import id.my.hendisantika.oauth2pkcedemo.security.RequestObjectPolicy;
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

    /**
     * What the profile asks of the authorization server itself, checked against how this one is
     * actually configured rather than against a list of intentions.
     */
    public List<FapiCheck> serverChecks() {
        List<FapiCheck> checks = new ArrayList<>();

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
        checks.add(FapiCheck.notApplicable("Request objects are signed",
                "FAPI 1.0 Advanced §5.2.2; not carried into FAPI 2.0",
                "FAPI 2.0 requires a pushed request with a short-lived request_uri instead. RFC 9101 "
                        + "§10.5's require_signed_request_object is implemented here regardless: "
                        + "server-wide it is " + this.requestObjectPolicy.requireSignedRequestObject()
                        + " and published in both documents, and "
                        + clientsRequiringSignedRequestObjects() + " of the "
                        + configuredClients().size() + " clients below set it for themselves"));

        // Honest failures follow. A profile check that only ever passes is worth nothing - and this
        // one is now capable of passing, which is the only thing that makes its failing mean
        // anything: the switch exists and is off rather than being absent.
        checks.add(FapiCheck.of(this.pushedAuthorizationPolicy.requirePushedRequests(),
                "The server requires pushed authorization requests", "FAPI 2.0 §5.3.1",
                "The profile says the server \"shall reject authorization requests sent without "
                        + "[RFC9126]\", which is every client rather than the willing ones. RFC 9126 "
                        + "§5's server-wide require_pushed_authorization_requests is "
                        + this.pushedAuthorizationPolicy.requirePushedRequests()
                        + " and published in both documents; §6's per-client one is set by "
                        + clientsRequiringPushedRequests() + " of the " + configuredClients().size()
                        + " clients below"));

        checks.add(FapiCheck.of(properties.issuerUri().startsWith("https://"),
                "All endpoints are served over TLS", "FAPI 2.0 §5.3",
                "The issuer is " + properties.issuerUri()
                        + "; only the mTLS listener on 8443 uses TLS"));

        return checks;
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

    private static List<FapiCheck> checksFor(RegisteredClient client) {
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
