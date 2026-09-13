package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 12.56
 */
public record PkceExchange(String registrationId,
                           String state,
                           String codeVerifier,
                           String codeChallenge,
                           String codeChallengeMethod,
                           String authorizationRequestUri,
                           Instant startedAt) implements Serializable {
}
