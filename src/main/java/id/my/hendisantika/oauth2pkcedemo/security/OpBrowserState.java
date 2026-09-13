package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 20.25
 */
public final class OpBrowserState {

    /**
     * OpenID Connect Session Management section 3.2: the OP's own record of the user agent's login
     * state, "typically going to be stored in a cookie or HTML5 local storage" and origin bound to
     * the authorization server. Readable by script on purpose - the OP iframe is a page, and reading
     * this is the only thing it does.
     */
    public static final String COOKIE_NAME = "op_browser_state";

    private static final SecureRandom RANDOM = new SecureRandom();

    private OpBrowserState() {
    }

    public static Optional<String> current(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        return Arrays.stream(cookies)
                .filter(cookie -> COOKIE_NAME.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }

    /**
     * Changes the state, which is what makes the next poll answer {@code changed}. The
     * specification asks for this on "meaningful events": a login, a logout, a different user.
     */
    public static String refresh(HttpServletResponse response) {
        byte[] value = new byte[16];
        RANDOM.nextBytes(value);
        String state = Base64.getUrlEncoder().withoutPadding().encodeToString(value);

        Cookie cookie = new Cookie(COOKIE_NAME, state);
        cookie.setPath("/");
        // Not HttpOnly: the OP iframe has to read it from script to recompute the session state.
        cookie.setHttpOnly(false);
        response.addCookie(cookie);
        return state;
    }

    public static String ensure(HttpServletRequest request, HttpServletResponse response) {
        return current(request).orElseGet(() -> refresh(response));
    }

    /**
     * Section 3.2, in the shape the specification's own pseudo-code uses: a hash of the client, the
     * origin the response went to, the state above and a fresh salt, with the salt appended so that
     * the browser can recompute the same value later.
     */
    public static String sessionState(String clientId, String origin, String browserState, String salt) {
        String material = clientId + " " + origin + " " + browserState + " " + salt;
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(material.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest) + "." + salt;
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to compute the session state", ex);
        }
    }

    public static String newSalt() {
        byte[] salt = new byte[8];
        RANDOM.nextBytes(salt);
        return HexFormat.of().formatHex(salt);
    }

    /**
     * RFC 6454 section 4, as the specification asks: scheme, host and port of where the
     * authorization response was sent, and nothing else.
     */
    public static String originOf(String uri) {
        URI parsed = URI.create(uri);
        StringBuilder origin = new StringBuilder(parsed.getScheme()).append("://").append(parsed.getHost());
        if (parsed.getPort() != -1) {
            origin.append(':').append(parsed.getPort());
        }
        return origin.toString();
    }
}
