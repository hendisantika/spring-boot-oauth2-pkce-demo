package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 16/09/26
 * Time: 09.20
 */
public record RequestEncryptionAlgRun(String defaultAlg,
                                      List<String> supportedAlgs,
                                      List<RequestEncryptionAlgAttempt> attempts,
                                      Instant ranAt) implements Serializable {

    public long accepted() {
        return attempts.stream().filter(RequestEncryptionAlgAttempt::accepted).count();
    }

    /**
     * The claim the page is making about every encrypted row: acted on exactly when the JWE header
     * matched the registration. The unencrypted row is deliberately not part of it - registering an
     * algorithm is not a promise to use one.
     */
    public boolean everyEncryptedRowMatchedItsRegistration() {
        return attempts.stream()
                .filter(RequestEncryptionAlgAttempt::encrypted)
                .allMatch(attempt -> !attempt.accepted() || attempt.matchesRegistration());
    }

    /** An algorithm can match the registration and still be one this server never implemented. */
    public boolean someRowMatchedItsRegistrationAndWasStillRefused() {
        return attempts.stream()
                .anyMatch(attempt -> attempt.matchesRegistration() && !attempt.accepted());
    }
}
