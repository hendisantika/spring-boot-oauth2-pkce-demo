package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 17/09/26
 * Time: 16.05
 */
public record RequestUriMetadataAttempt(String label,
                                        String description,
                                        String parameter,
                                        String value,
                                        String metadataSaid,
                                        boolean accepted,
                                        String outcome) implements Serializable {

    /** Long references are shown as their first characters; the page is about the kind, not the id. */
    public String shortValue() {
        return value.length() <= 52 ? value : value.substring(0, 52) + "…";
    }
}
