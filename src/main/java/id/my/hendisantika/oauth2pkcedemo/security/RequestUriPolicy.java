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
 * Time: 21.30
 */
@Slf4j
public final class RequestUriPolicy {

    /**
     * OpenID Connect Discovery section 3 defaults this to false. True here, because RFC 9101
     * section 10.4.1's first mitigation against pointing a server at an arbitrary URL is checking
     * "that the value of the request_uri parameter does not point to an unexpected location", and a
     * registered list is how a server knows which locations are expected.
     */
    public static final boolean REQUIRE_REGISTRATION_DEFAULT = true;

    private final AtomicBoolean requireRegistration;

    public RequestUriPolicy(boolean requireRegistration) {
        this.requireRegistration = new AtomicBoolean(requireRegistration);
    }

    public boolean requireRegistration() {
        return this.requireRegistration.get();
    }

    /** @return what it was before, so a caller can put it back */
    public boolean requireRegistration(boolean required) {
        boolean previous = this.requireRegistration.getAndSet(required);
        if (previous != required) {
            log.info("require_request_uri_registration is now {}", required);
        }
        return previous;
    }
}
