package id.my.hendisantika.oauth2pkcedemo.security;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 18.33
 */
public record PendingMixUp(String state,
                           String codeVerifier,
                           String codeChallenge,
                           String expectedIssuer,
                           boolean checkIssuer) {

    /**
     * What the client wrote down when it sent the user away, and the whole basis on which it will
     * decide where to send the authorization code next. Nothing here comes back from the network -
     * which is exactly why an unidentified response can be attributed to the wrong server.
     */
    public boolean belongsTo(String state) {
        return this.state.equals(state);
    }
}
