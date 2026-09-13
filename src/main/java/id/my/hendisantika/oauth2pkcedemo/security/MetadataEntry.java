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
public record MetadataEntry(String name,
                            String value,
                            String requirement,
                            String definedBy,
                            boolean inBothDocuments) implements Serializable {

    /** A field RFC 8414 section 2 says a server must publish. */
    public boolean required() {
        return "REQUIRED".equals(requirement);
    }
}
