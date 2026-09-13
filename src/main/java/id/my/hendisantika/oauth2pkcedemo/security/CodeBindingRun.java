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
 * Time: 17.48
 */
public record CodeBindingRun(boolean bound,
                             String thumbprint,
                             String publicJwk,
                             Map<String, String> authorizationParameters,
                             String authorizationCode,
                             List<CodeBindingAttempt> attempts,
                             Instant ranAt) implements Serializable {

    public CodeBindingRun {
        authorizationParameters = new TreeMap<>(authorizationParameters);
    }

    /**
     * Whether anyone holding the code and the verifier could redeem it. The unbound run is expected
     * to say yes, which is the comparison the page is built around.
     */
    public boolean redeemableWithoutTheKey() {
        return attempts.stream()
                .anyMatch(attempt -> attempt.proofThumbprint() == null && attempt.isSuccess());
    }
}
