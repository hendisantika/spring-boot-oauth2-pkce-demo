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
 * Date: 13/09/26
 * Time: 18.33
 */
public record MixUpRun(boolean checkedIssuer,
                       String expectedIssuer,
                       String receivedIssuer,
                       List<MixUpStep> steps,
                       String outcome,
                       boolean codeLeaked,
                       String stolenTokenSubject,
                       Instant ranAt) implements Serializable {

    /** The two identities differ in every run; the only question is whether anyone looked. */
    public boolean issuerMatches() {
        return receivedIssuer != null && receivedIssuer.equals(expectedIssuer);
    }
}
