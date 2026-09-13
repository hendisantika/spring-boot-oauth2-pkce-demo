package id.my.hendisantika.oauth2pkcedemo.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 15.10
 */
public final class AuthenticationFreshness {

    public static final String MAX_AGE = "max_age";

    private AuthenticationFreshness() {
    }

    /**
     * When the user last proved something, which is what OpenID Connect Core section 2 means by
     * {@code auth_time}. Spring Authorization Server computes it the same way -
     * {@code JwtGenerator.getAuthenticationTime} takes the <em>latest</em>
     * {@link FactorGrantedAuthority}, not the first - so a step-up moves this forward rather than
     * leaving it at the password.
     */
    public static Instant authenticatedAt(Authentication authentication) {
        Instant latest = null;
        if (authentication == null) {
            return null;
        }
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if (authority instanceof FactorGrantedAuthority factor
                    && (latest == null || factor.getIssuedAt().isAfter(latest))) {
                latest = factor.getIssuedAt();
            }
        }
        return latest;
    }

    /** Each factor and the moment it was satisfied, so the page can show where auth_time came from. */
    public static Map<String, Instant> factors(Authentication authentication) {
        Map<String, Instant> factors = new LinkedHashMap<>();
        if (authentication == null) {
            return factors;
        }
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if (authority instanceof FactorGrantedAuthority factor) {
                factors.put(factor.getAuthority(), factor.getIssuedAt());
            }
        }
        return factors;
    }

    public static Long ageSeconds(Authentication authentication) {
        Instant authenticatedAt = authenticatedAt(authentication);
        return authenticatedAt == null ? null : Duration.between(authenticatedAt, Instant.now()).toSeconds();
    }

    /**
     * OpenID Connect Core section 3.1.2.1: if the elapsed time since the authentication is greater
     * than {@code max_age}, the server must actively re-authenticate the user. Equal is still fresh
     * enough; {@code max_age=0} therefore asks for a new authentication every time.
     */
    public static boolean satisfies(Authentication authentication, Long maxAgeSeconds) {
        return satisfies(authenticatedAt(authentication), maxAgeSeconds);
    }

    /** The same rule against a moment already read from a token. */
    public static boolean satisfies(Instant authenticatedAt, Long maxAgeSeconds) {
        if (maxAgeSeconds == null) {
            return true;
        }
        if (authenticatedAt == null) {
            return false;
        }
        // Zero is taken to mean "prove it again now", the reading every implementation shares. Read
        // strictly it would mean almost nothing: an authentication that has just happened has an
        // elapsed time of zero at any resolution, zero is not greater than zero, and the parameter
        // would never ask for anything. The filter needs its own guard against bouncing for ever
        // because of this.
        if (maxAgeSeconds == 0) {
            return false;
        }
        return Duration.between(authenticatedAt, Instant.now()).toSeconds() <= maxAgeSeconds;
    }

    /** {@code max_age} is a number of seconds; anything else is not a request this can act on. */
    public static Long parse(String maxAge) {
        try {
            long value = Long.parseLong(maxAge.trim());
            return value < 0 ? null : value;
        } catch (RuntimeException ex) {
            return null;
        }
    }
}
