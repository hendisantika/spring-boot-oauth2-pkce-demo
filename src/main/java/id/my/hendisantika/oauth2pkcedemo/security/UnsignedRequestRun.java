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
 * Time: 14.30
 */
public record UnsignedRequestRun(boolean serverRequiresSignedRequestObjects,
                                 List<String> supportedAlgs,
                                 List<UnsignedRequestAttempt> attempts,
                                 Instant ranAt) implements Serializable {

    public long accepted() {
        return attempts.stream().filter(UnsignedRequestAttempt::accepted).count();
    }

    /** Every accepted row is an unsigned one, which is the whole claim the page is making. */
    public boolean everyAcceptedRowWasUnsigned() {
        return attempts.stream().filter(UnsignedRequestAttempt::accepted)
                .noneMatch(UnsignedRequestAttempt::signed);
    }

    /** Nothing was accepted from a client that registered the downgrade defence. */
    public boolean nothingAcceptedWhereSigningWasRequired() {
        return attempts.stream()
                .noneMatch(attempt -> attempt.accepted() && attempt.requireSignedRegistered());
    }
}
