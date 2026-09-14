package id.my.hendisantika.oauth2pkcedemo.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 23.05
 */
@Slf4j
@Component
public class DpopNonceStore {

    /** Long enough for a client to retry immediately, short enough to be worth having. */
    public static final Duration LIFETIME = Duration.ofMinutes(5);

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, Instant> issued = new ConcurrentHashMap<>();

    /** A value only this server could have produced, remembered until it is spent or expires. */
    public String issue() {
        byte[] value = new byte[16];
        RANDOM.nextBytes(value);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(value);
        issued.put(nonce, Instant.now().plus(LIFETIME));
        sweep();
        return nonce;
    }

    /**
     * Spends a nonce. Single use is this server's choice, not the specification's: RFC 9449 leaves
     * the lifetime and reuse policy to whoever issues them, and a nonce good until it expires is
     * equally conformant. Spending it makes the difference visible on the page.
     *
     * @return whether the nonce was one this server issued and had not already been used
     */
    public boolean spend(String nonce) {
        if (nonce == null) {
            return false;
        }
        Instant expiresAt = issued.remove(nonce);
        boolean valid = expiresAt != null && Instant.now().isBefore(expiresAt);
        log.debug("DPoP nonce {} was {}", nonce, valid ? "accepted" : "not one to accept");
        return valid;
    }

    public boolean knows(String nonce) {
        return nonce != null && issued.containsKey(nonce);
    }

    private void sweep() {
        Instant now = Instant.now();
        issued.entrySet().removeIf(entry -> now.isAfter(entry.getValue()));
    }
}
