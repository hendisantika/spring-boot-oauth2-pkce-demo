package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.14
 */
public record RegistrationRun(Map<String, Object> requestedMetadata,
                              Map<String, Object> issuedMetadata,
                              String clientId,
                              String registrationClientUri,
                              boolean requireProofKey,
                              boolean requireAuthorizationConsent,
                              List<String> grantedScopes,
                              List<RegistrationAttempt> attempts,
                              Instant ranAt) implements Serializable {

    public RegistrationRun {
        issuedMetadata = new TreeMap<>(issuedMetadata);
    }

    public boolean registered() {
        return clientId != null;
    }

    /**
     * Registration hands out an identity, not authority. Nothing here asked for a scope - the server
     * refuses a request that does - so the new client can name itself and nothing more.
     */
    public boolean hasNoScopes() {
        return grantedScopes.isEmpty();
    }
}
