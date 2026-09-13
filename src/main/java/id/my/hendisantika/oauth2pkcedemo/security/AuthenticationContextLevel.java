package id.my.hendisantika.oauth2pkcedemo.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 16.52
 */
public final class AuthenticationContextLevel {

    /** One factor: a password and nothing else. */
    public static final String LOA_1 = "urn:demo:loa:1";

    /** Two factors: a password plus a one-time code. */
    public static final String LOA_2 = "urn:demo:loa:2";

    private AuthenticationContextLevel() {
    }

    /**
     * Reads the factors Spring Security recorded on the authentication and names the level they add
     * up to. {@code acr} is the level; {@code amr} is the list of methods that got there.
     */
    public static String acrOf(Authentication authentication) {
        return amrOf(authentication).size() >= 2 ? LOA_2 : LOA_1;
    }

    /**
     * OpenID Connect Core section 2 defines {@code amr} as method identifiers; RFC 8176 registers the
     * values used here.
     */
    public static List<String> amrOf(Authentication authentication) {
        Set<String> methods = new LinkedHashSet<>();
        if (authentication == null) {
            return List.of();
        }
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            switch (authority.getAuthority()) {
                case FactorGrantedAuthority.PASSWORD_AUTHORITY -> methods.add("pwd");
                case FactorGrantedAuthority.OTT_AUTHORITY -> methods.add("otp");
                case FactorGrantedAuthority.WEBAUTHN_AUTHORITY -> methods.add("hwk");
                case FactorGrantedAuthority.X509_AUTHORITY -> methods.add("swk");
                default -> {
                    // Ordinary role authorities say nothing about how the user authenticated.
                }
            }
        }
        return List.copyOf(methods);
    }

    /** Whether the session already meets the level a client asked for with {@code acr_values}. */
    public static boolean satisfies(Authentication authentication, String requestedAcr) {
        if (requestedAcr == null || requestedAcr.isBlank()) {
            return true;
        }
        // acr_values is a space-separated list of acceptable values, most preferred first.
        for (String candidate : requestedAcr.split(" ")) {
            if (LOA_1.equals(candidate)) {
                return true;
            }
            if (LOA_2.equals(candidate) && LOA_2.equals(acrOf(authentication))) {
                return true;
            }
        }
        return false;
    }
}
