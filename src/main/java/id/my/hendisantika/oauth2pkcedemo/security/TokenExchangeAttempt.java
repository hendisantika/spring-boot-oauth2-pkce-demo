package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 15.04
 */
public record TokenExchangeAttempt(String label,
                                   String description,
                                   Map<String, String> requestParameters,
                                   int statusCode,
                                   String error,
                                   Map<String, Object> tokenClaims,
                                   String issuedTokenType) implements Serializable {

    public boolean isSuccess() {
        return statusCode == 200;
    }

    /**
     * RFC 8693 section 4.1: delegation is marked by an {@code act} claim naming who is acting. Its
     * absence means the exchanged token simply impersonates the subject.
     */
    public boolean isDelegation() {
        return tokenClaims != null && tokenClaims.containsKey("act");
    }
}
