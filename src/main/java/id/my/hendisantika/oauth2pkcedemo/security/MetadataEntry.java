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
                            boolean inOauthDocument,
                            boolean inOidcDocument,
                            String demonstratedAt) implements Serializable {

    /** A field RFC 8414 section 2 says a server must publish. */
    public boolean required() {
        return "REQUIRED".equals(requirement);
    }

    /** Published by both documents, which is true of everything the two specifications share. */
    public boolean inBothDocuments() {
        return inOauthDocument && inOidcDocument;
    }

    /** Which document has it, for the field that only one of them defines. */
    public String onlyIn() {
        if (inBothDocuments()) {
            return null;
        }
        return inOauthDocument ? "the OAuth document" : "the OpenID document";
    }

    /** Whether somewhere in this demo shows what the value does, rather than only what it says. */
    public boolean hasDemonstration() {
        return demonstratedAt != null && !demonstratedAt.isBlank();
    }
}
