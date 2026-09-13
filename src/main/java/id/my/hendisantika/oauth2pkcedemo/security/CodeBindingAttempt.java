package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 17.48
 */
public record CodeBindingAttempt(String label,
                                 String description,
                                 String proofThumbprint,
                                 int statusCode,
                                 String outcome,
                                 String tokenType,
                                 String confirmationThumbprint) implements Serializable {

    public boolean isSuccess() {
        return statusCode == 200;
    }

    /** What the attempt put in the {@code DPoP} header, for the column that shows it. */
    public String proofDescription() {
        return proofThumbprint == null ? "no proof" : proofThumbprint;
    }
}
