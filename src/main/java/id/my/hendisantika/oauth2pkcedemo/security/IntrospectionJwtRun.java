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
 * Time: 08.15
 */
public record IntrospectionJwtRun(String introspectedBy,
                                  String alsoIntrospectedBy,
                                  List<IntrospectionResponseAttempt> attempts,
                                  Instant ranAt) implements Serializable {

    /** Every signed answer should verify against the published keys, including the negative one. */
    public boolean everySignatureVerified() {
        return attempts.stream()
                .filter(IntrospectionResponseAttempt::signed)
                .allMatch(attempt -> Boolean.TRUE.equals(attempt.signatureVerifies()));
    }
}
