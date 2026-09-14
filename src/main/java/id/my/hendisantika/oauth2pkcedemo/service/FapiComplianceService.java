package id.my.hendisantika.oauth2pkcedemo.service;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.FapiCheck;
import id.my.hendisantika.oauth2pkcedemo.security.IssuerIdentifierResponseHandler;
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

    private final RegisteredClientRepository registeredClientRepository;
    private final AuthorizationServerSettings settings;
    /** The handler that actually sends authorization responses, so the check below is about it. */
    private final ObjectProvider<IssuerIdentifierResponseHandler> issuerIdentifierResponseHandler;
    private final DemoProperties properties;

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

        // Honest failures follow. A profile check that only ever passes is worth nothing.
        checks.add(FapiCheck.fail("The server requires pushed authorization requests",
                "FAPI 2.0 §5.3.1",
                "ClientSettings has no require_pushed_authorization_requests, so a client may still "
                        + "send an ordinary authorization request"));

        checks.add(FapiCheck.of(properties.issuerUri().startsWith("https://"),
                "All endpoints are served over TLS", "FAPI 2.0 §5.3",
                "The issuer is " + properties.issuerUri()
                        + "; only the mTLS listener on 8443 uses TLS"));

        return checks;
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
                properties.requestUriClient(), properties.rarClient());
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
