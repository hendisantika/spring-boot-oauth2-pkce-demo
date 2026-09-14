package id.my.hendisantika.oauth2pkcedemo.security;

import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 17/09/26
 * Time: 08.15
 */
@Slf4j
public final class PushedAuthorizationPolicy {

    /** What a deployment starts with, and what the page puts back after a run. */
    public static final boolean REQUIRE_PUSHED_REQUESTS_DEFAULT = false;

    /**
     * RFC 9126 section 5, as server metadata: "whether the authorization server accepts
     * authorization request data only via PAR". A deployment sets this once in configuration; here
     * it is a value that can be moved, so a page can show the same request refused and accepted
     * without restarting the server. While it is on it is on for every client.
     */
    private final AtomicBoolean requirePushedRequests;

    public PushedAuthorizationPolicy(boolean requirePushedRequests) {
        this.requirePushedRequests = new AtomicBoolean(requirePushedRequests);
    }

    public boolean requirePushedRequests() {
        return this.requirePushedRequests.get();
    }

    /** @return what it was before, so a caller can put it back */
    public boolean requirePushedRequests(boolean required) {
        boolean previous = this.requirePushedRequests.getAndSet(required);
        if (previous != required) {
            log.info("require_pushed_authorization_requests is now {}", required);
        }
        return previous;
    }
}
