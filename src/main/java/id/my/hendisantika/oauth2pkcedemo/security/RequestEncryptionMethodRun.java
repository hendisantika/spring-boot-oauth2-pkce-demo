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
 * Time: 12.05
 */
public record RequestEncryptionMethodRun(String defaultEnc,
                                         List<String> supportedEncs,
                                         List<RequestEncryptionMethodAttempt> attempts,
                                         Instant ranAt) implements Serializable {

    public long accepted() {
        return attempts.stream().filter(RequestEncryptionMethodAttempt::accepted).count();
    }

    /** Nothing whose content encryption method differed from its registration should be acted on. */
    public boolean everyAcceptedRowMatchedItsRegistration() {
        return attempts.stream()
                .allMatch(attempt -> !attempt.accepted() || attempt.matchesRegistration());
    }

    /** Only CBC pads, so only CBC rows carry more ciphertext than they were given payload. */
    public boolean onlyCbcPadded() {
        return attempts.stream().allMatch(attempt ->
                attempt.sentEnc().contains("CBC") == (attempt.overhead() > 0));
    }
}
