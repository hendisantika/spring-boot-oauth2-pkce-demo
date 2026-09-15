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
                            String demonstratedAt,
                            Counterpart counterpart) implements Serializable {

    /**
     * The client registration parameter a server field governs. The discovery documents describe
     * only the server, so a client parameter can never be a row here - but several of these fields
     * exist precisely to tell a client what it may register, and the pairing is most of what they
     * mean. {@code request_object_signing_alg_values_supported} is a list of what a client may put
     * in {@code request_object_signing_alg}, and RFC 9101 section 10.1 then has the server refuse a
     * request object signed with anything other than the one it chose.
     *
     * @param name          the client parameter, which is sometimes the same word as the server one
     * @param definedBy     where that parameter is defined, which is rarely the same document
     * @param demonstratedAt where this demo shows a client using it
     */
    public record Counterpart(String name, String definedBy, String demonstratedAt)
            implements Serializable {
    }

    /** Whether a client registers something this field constrains. */
    public boolean hasCounterpart() {
        return counterpart != null;
    }

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
