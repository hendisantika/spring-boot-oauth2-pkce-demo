package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 13.20
 */
@Slf4j
@RequiredArgsConstructor
public final class InsufficientUserAuthenticationHandler implements AccessDeniedHandler {

    private final String requiredAcr;
    private final long maxAgeSeconds;

    /**
     * RFC 9470 section 3. A token that is valid but was not earned strongly enough is answered with
     * {@code 401} and {@code error="insufficient_user_authentication"}, naming the level the
     * resource server wants - so the client knows to send the user back rather than simply failing.
     * <p>
     * Spring Security writes no such challenge. Its {@code BearerTokenAccessDeniedHandler} answers
     * {@code 403} with {@code insufficient_scope} (RFC 6750 section 3.1), which is the right answer
     * to a missing scope and the wrong one here: a scope is granted once, while an authentication
     * level can be raised by asking the user for another factor. The status matters too - 401 says
     * "authenticate again", 403 says "do not bother".
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        String challenge = "Bearer error=\"" + StepUpChallenge.INSUFFICIENT_USER_AUTHENTICATION + "\", "
                + "error_description=\"A higher authentication level is required for this operation\", "
                + "acr_values=\"" + requiredAcr + "\", "
                + "max_age=\"" + maxAgeSeconds + "\"";

        log.debug("Answering {} with a step-up challenge for {}", request.getRequestURI(), requiredAcr);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, challenge);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + StepUpChallenge.INSUFFICIENT_USER_AUTHENTICATION + "\"}");
    }
}
