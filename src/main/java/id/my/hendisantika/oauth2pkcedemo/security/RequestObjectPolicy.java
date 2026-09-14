package id.my.hendisantika.oauth2pkcedemo.security;

import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 16/09/26
 * Time: 17.20
 */
@Slf4j
public final class RequestObjectPolicy {

    /**
     * RFC 9101 section 10.5, as server metadata. A deployment sets this once in configuration; here
     * it is a value that can be moved, so a page can show the same request refused and accepted
     * without restarting the server. While it is on it is on for every client, which is what "server
     * metadata" means.
     */
    private final AtomicBoolean requireSignedRequestObject;

    public RequestObjectPolicy(boolean requireSignedRequestObject) {
        this.requireSignedRequestObject = new AtomicBoolean(requireSignedRequestObject);
    }

    public boolean requireSignedRequestObject() {
        return this.requireSignedRequestObject.get();
    }

    /** @return what it was before, so a caller can put it back */
    public boolean requireSignedRequestObject(boolean required) {
        boolean previous = this.requireSignedRequestObject.getAndSet(required);
        if (previous != required) {
            log.info("require_signed_request_object is now {}", required);
        }
        return previous;
    }
}
