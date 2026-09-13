package id.my.hendisantika.oauth2pkcedemo.security;

import java.time.Instant;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 21.06
 */
public record PendingRefreshBinding(String deviceCode,
                                    String userCode,
                                    DpopKeyPair key,
                                    Instant requestedAt) {

    /**
     * The key is generated before the device code is asked for and kept until the token comes back,
     * because everything the run is about is whether what comes back is still tied to it.
     */
    public String thumbprint() {
        return key.thumbprint();
    }
}
