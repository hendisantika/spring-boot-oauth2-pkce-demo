package id.my.hendisantika.oauth2pkcedemo.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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
 * Time: 13.21
 */
@Component
@RequiredArgsConstructor
public class OAuth2LoginRequiredInterceptor implements HandlerInterceptor {

    private final DemoProperties properties;

    /**
     * The demo pages read tokens off an {@link OAuth2AuthenticationToken}, but signing in at the
     * authorization server's own login form also satisfies {@code authenticated()} - land on
     * /dashboard that way and argument resolution would fail with a 500. Send those sessions
     * through the client's PKCE flow instead.
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof OAuth2AuthenticationToken) {
            return true;
        }
        response.sendRedirect(request.getContextPath()
                + "/oauth2/authorization/" + properties.client().registrationId());
        return false;
    }
}
