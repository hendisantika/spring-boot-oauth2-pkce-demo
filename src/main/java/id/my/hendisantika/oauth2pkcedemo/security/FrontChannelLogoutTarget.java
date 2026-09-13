package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 20.09
 */
public record FrontChannelLogoutTarget(String clientName,
                                       String registrationId,
                                       String uri,
                                       boolean sessionRequired) implements Serializable {

    /**
     * OpenID Connect Front-Channel Logout section 2: a client that asked for the session to be
     * named gets {@code iss} and {@code sid} on the query string, and one that did not gets a bare
     * URI and has to work out for itself which of its sessions this is about.
     */
    public String describeParameters() {
        return sessionRequired ? "iss and sid" : "none";
    }
}
