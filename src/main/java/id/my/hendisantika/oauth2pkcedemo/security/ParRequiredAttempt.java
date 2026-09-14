package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 16/09/26
 * Time: 22.40
 */
public record ParRequiredAttempt(String label,
                                 String description,
                                 String clientId,
                                 boolean clientRequiresPar,
                                 String carried,
                                 boolean accepted,
                                 String refusedBy,
                                 String outcome) implements Serializable {

    /** The filter added here, rather than anything Spring Authorization Server does. */
    public static final String THIS_FILTER = "the client's registration";

    /** Spring Authorization Server's own validation of the reference. */
    public static final String THE_SERVER = "the authorization server";
}
