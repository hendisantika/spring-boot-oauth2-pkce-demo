package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 18/09/26
 * Time: 20.25
 */
public record EncryptionAlgValuesRun(Object advertised,
                                     List<Map<String, String>> publishedKeys,
                                     List<EncryptionAlgValuesAttempt> attempts,
                                     Instant ranAt) implements Serializable {

    public long accepted() {
        return attempts.stream().filter(EncryptionAlgValuesAttempt::accepted).count();
    }

    /** Every published key says what it is for, so a client need not guess between the two RSA ones. */
    public boolean everyKeySaysWhatItIsFor() {
        return publishedKeys.stream().allMatch(key -> key.get("use") != null
                && !key.get("use").isBlank());
    }

    /**
     * The claim the page is making: a request object was unwrapped exactly when its algorithm was
     * advertised, was the one the client registered, and it was addressed to the encryption key.
     */
    public boolean acceptedOnlyWithAllThree() {
        return attempts.stream().allMatch(attempt -> attempt.accepted()
                == (attempt.advertised() && attempt.itsOwnAlgorithm() && attempt.toTheEncryptionKey()));
    }
}
