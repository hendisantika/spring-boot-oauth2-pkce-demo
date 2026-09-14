package id.my.hendisantika.oauth2pkcedemo.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 16/09/26
 * Time: 20.05
 */
@Slf4j
public final class RequestObjectClientRegistrationConverters {

    /** RFC 9101 section 10.5, as the client metadata name a registration request carries. */
    public static final String REQUIRE_SIGNED_REQUEST_OBJECT = "require_signed_request_object";

    /** OpenID Connect Dynamic Client Registration, section 2. */
    public static final String REQUEST_OBJECT_SIGNING_ALG = "request_object_signing_alg";

    /** RFC 9126 section 6, which is client metadata for the same reason and dropped the same way. */
    public static final String REQUIRE_PAR = "require_pushed_authorization_requests";

    private RequestObjectClientRegistrationConverters() {
    }

    /**
     * Reading a registration request. Spring Authorization Server's own converter has a field for
     * every metadata name it knows and drops the rest, so these three arrive and go nowhere; this
     * puts them where the filters that enforce them read them from.
     */
    public static Converter<OidcClientRegistration, RegisteredClient> registeredClient() {
        Converter<OidcClientRegistration, RegisteredClient> delegate =
                new OidcClientRegistrationRegisteredClientConverter();
        return registration -> {
            RegisteredClient client = delegate.convert(registration);
            if (client == null) {
                return null;
            }
            Object requireSigned = registration.getClaim(REQUIRE_SIGNED_REQUEST_OBJECT);
            Object signingAlg = registration.getClaim(REQUEST_OBJECT_SIGNING_ALG);
            Object requirePar = registration.getClaim(REQUIRE_PAR);
            if (requireSigned == null && signingAlg == null && requirePar == null) {
                return client;
            }

            ClientSettings.Builder settings = ClientSettings.withSettings(
                    new LinkedHashMap<>(client.getClientSettings().getSettings()));
            if (requireSigned != null) {
                settings.setting(JwtSecuredAuthorizationRequestFilter.REQUIRE_SIGNED_SETTING,
                        Boolean.parseBoolean(String.valueOf(requireSigned)));
            }
            if (signingAlg != null) {
                settings.setting(JwtSecuredAuthorizationRequestFilter.SIGNING_ALG_SETTING,
                        String.valueOf(signingAlg));
            }
            if (requirePar != null) {
                settings.setting(PushedAuthorizationRequiredFilter.REQUIRE_PAR_SETTING,
                        Boolean.parseBoolean(String.valueOf(requirePar)));
            }
            log.debug("Registering [{}] with {}={}, {}={}", client.getClientId(),
                    REQUIRE_SIGNED_REQUEST_OBJECT, requireSigned, REQUEST_OBJECT_SIGNING_ALG,
                    signingAlg);
            return RegisteredClient.from(client).clientSettings(settings.build()).build();
        };
    }

    /**
     * Writing the registration response. RFC 7591 section 3.2.1: the response describes the client
     * as the server now holds it, so a metadata value the server kept and does not echo is one the
     * caller has no way to confirm.
     */
    public static Converter<RegisteredClient, OidcClientRegistration> clientRegistration() {
        Converter<RegisteredClient, OidcClientRegistration> delegate =
                new RegisteredClientOidcClientRegistrationConverter();
        return client -> {
            OidcClientRegistration registration = delegate.convert(client);
            if (registration == null) {
                return null;
            }
            Map<String, Object> claims = new LinkedHashMap<>(registration.getClaims());
            copy(client, JwtSecuredAuthorizationRequestFilter.REQUIRE_SIGNED_SETTING,
                    REQUIRE_SIGNED_REQUEST_OBJECT, claims);
            copy(client, JwtSecuredAuthorizationRequestFilter.SIGNING_ALG_SETTING,
                    REQUEST_OBJECT_SIGNING_ALG, claims);
            copy(client, PushedAuthorizationRequiredFilter.REQUIRE_PAR_SETTING, REQUIRE_PAR, claims);
            return OidcClientRegistration.withClaims(claims).build();
        };
    }

    private static void copy(RegisteredClient client, String setting, String claim,
                             Map<String, Object> claims) {
        Object value = client.getClientSettings().getSetting(setting);
        if (value != null) {
            claims.put(claim, value);
        }
    }
}
