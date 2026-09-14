package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 16/09/26
 * Time: 20.05
 */
public record ClientRequiredAttempt(String label,
                                    String description,
                                    String clientId,
                                    String registered,
                                    String sent,
                                    boolean accepted,
                                    String outcome) implements Serializable {
}
