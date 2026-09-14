package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 18/09/26
 * Time: 09.40
 */
public record RegisteredRequestUriAttempt(String label,
                                          String description,
                                          String clientId,
                                          String requestUri,
                                          boolean onTheList,
                                          boolean accepted,
                                          String outcome) implements Serializable {

    /** The path and anything after it; the host is this application in every row. */
    public String shortUri() {
        int start = requestUri.indexOf("/", requestUri.indexOf("//") + 2);
        return start < 0 ? requestUri : requestUri.substring(start);
    }
}
