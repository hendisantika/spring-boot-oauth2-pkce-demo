package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.12
 */
public record DiscoveryAttempt(String label,
                               String description,
                               String expectedIssuer,
                               String fetchedFrom,
                               String documentIssuer,
                               boolean accepted,
                               String outcome) implements Serializable {
}
