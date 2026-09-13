package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 13.40
 */
public record ResourceCallAttempt(String label,
                                  String tokenAcr,
                                  int statusCode,
                                  String body,
                                  StepUpChallenge challenge,
                                  Instant calledAt) implements Serializable {

    public boolean isSuccess() {
        return statusCode == 200;
    }
}
