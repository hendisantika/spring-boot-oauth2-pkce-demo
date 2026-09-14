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
 * Date: 15/09/26
 * Time: 20.40
 */
public record JarmEncryptionMethodRun(List<JarmEncryptionMethodAttempt> attempts,
                                      boolean everyPayloadWasASignedJwt,
                                      Instant ranAt) implements Serializable {

    public long encrypted() {
        return attempts.stream().filter(JarmEncryptionMethodAttempt::encrypted).count();
    }
}
