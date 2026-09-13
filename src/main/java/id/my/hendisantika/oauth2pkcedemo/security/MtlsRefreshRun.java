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
 * Date: 14/09/26
 * Time: 09.12
 */
public record MtlsRefreshRun(String clientId,
                             String certificateThumbprint,
                             String strangerThumbprint,
                             String accessTokenConfirmation,
                             boolean refreshTokenIssued,
                             List<MtlsRefreshAttempt> attempts,
                             Instant ranAt) implements Serializable {

    /** Whether anything but the registered certificate got a token out of the refresh endpoint. */
    public boolean onlyTheRegisteredCertificateWorked() {
        return attempts.stream().filter(MtlsRefreshAttempt::isSuccess).count() == 1;
    }
}
