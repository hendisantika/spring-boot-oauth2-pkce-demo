package id.my.hendisantika.oauth2pkcedemo.security;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 17.48
 */
public record PendingCodeBinding(boolean bound,
                                 DpopKeyPair key,
                                 String codeVerifier,
                                 String codeChallenge,
                                 String state) {

    /**
     * The key the code is being tied to, or {@code null} for the unbound run - the comparison the
     * whole demo turns on.
     */
    public String thumbprint() {
        return key == null ? null : key.thumbprint();
    }
}
