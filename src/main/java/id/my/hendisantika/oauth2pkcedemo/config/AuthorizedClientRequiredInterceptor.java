package id.my.hendisantika.oauth2pkcedemo.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.56
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuthorizedClientRequiredInterceptor implements HandlerInterceptor {

    private final OAuth2AuthorizedClientService authorizedClientService;

    /**
     * The token pages read from the authorized client store, and a session can outlive what is in
     * it - the row is dropped, or the tokens are cleared out from underneath. Authentication still
     * looks fine at that point, so without this the pages dereference a null and return a 500.
     * Send the session through the flow again to pick up a fresh token instead.
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Authentication)) {
            // OAuth2LoginRequiredInterceptor has already dealt with this case.
            return true;
        }
        String registrationId = oauth2Authentication.getAuthorizedClientRegistrationId();
        if (authorizedClientService.loadAuthorizedClient(registrationId, authentication.getName()) != null) {
            return true;
        }

        log.debug("No authorized client stored for [{}] / [{}]; restarting the flow",
                registrationId, authentication.getName());
        request.getSession().invalidate();
        SecurityContextHolder.clearContext();
        response.sendRedirect(request.getContextPath() + "/oauth2/authorization/" + registrationId);
        return false;
    }
}
