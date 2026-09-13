package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 15.52
 */
@Slf4j
public final class RichAuthorizationRequestValidator implements AuthenticationConverter {

    public static final String AUTHORIZATION_DETAILS = "authorization_details";

    /**
     * Spring Authorization Server has no RFC 9396 support, so nothing checks
     * {@code authorization_details} before it is stored and consented to. Registered as a converter
     * on the authorization endpoint purely to inspect the request: it always returns {@code null} so
     * the real converter still runs, and throws when the request asks for a type this server does
     * not implement.
     * <p>
     * RFC 9396 section 5 calls for {@code invalid_authorization_details} in exactly this case.
     */
    @Override
    public Authentication convert(HttpServletRequest request) {
        String authorizationDetails = request.getParameter(AUTHORIZATION_DETAILS);
        if (!StringUtils.hasText(authorizationDetails)) {
            return null;
        }

        List<String> unsupported;
        try {
            unsupported = RichAuthorizationDetail.unsupportedTypes(authorizationDetails);
        } catch (IllegalArgumentException ex) {
            throw error("authorization_details must be a JSON array of objects");
        }
        if (!unsupported.isEmpty()) {
            log.debug("Rejecting authorization_details with unsupported types {}", unsupported);
            throw error("Unsupported authorization details type: " + String.join(", ", unsupported));
        }
        return null;
    }

    private static OAuth2AuthenticationException error(String description) {
        return new OAuth2AuthenticationException(new OAuth2Error(
                "invalid_authorization_details", description,
                "https://datatracker.ietf.org/doc/html/rfc9396#section-5"));
    }
}
