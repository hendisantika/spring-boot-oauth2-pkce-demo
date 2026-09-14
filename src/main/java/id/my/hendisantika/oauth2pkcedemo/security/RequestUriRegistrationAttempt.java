package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 17/09/26
 * Time: 21.30
 */
public record RequestUriRegistrationAttempt(String label,
                                            String description,
                                            String requestUri,
                                            boolean registeredForThisClient,
                                            boolean acceptedWhenRequired,
                                            String outcomeWhenRequired,
                                            boolean acceptedWhenNotRequired,
                                            String outcomeWhenNotRequired) implements Serializable {

    /** The rows the registration requirement is the whole difference for. */
    public boolean changedWithTheSetting() {
        return acceptedWhenRequired != acceptedWhenNotRequired;
    }

    /** The path, which is what distinguishes these; the host is this application either way. */
    public String path() {
        int start = requestUri.indexOf("/", requestUri.indexOf("//") + 2);
        return start < 0 ? requestUri : requestUri.substring(start);
    }
}
