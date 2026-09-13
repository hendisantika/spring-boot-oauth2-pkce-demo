package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

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
public class RestartOAuth2LoginFilter extends OncePerRequestFilter {

    private final RequestMatcher authorizationRequestMatcher =
            PathPatternRequestMatcher.withDefaults().matcher("/oauth2/authorization/**");

    /**
     * Client and authorization server run in one application and therefore share one
     * {@code SecurityContext}. Once a login completes, that context holds an
     * {@link OAuth2AuthenticationToken} - and if a second authorization request starts from the same
     * session, the authorization server treats that token as the end user. It cannot derive
     * {@code auth_time} from it (Spring Security 7 reads that off a {@code FactorGrantedAuthority},
     * which only an interactive login attaches), so minting the ID token fails with
     * "authenticationTime cannot be null" and the user gets a 500.
     * <p>
     * Reachable by signing in, then starting any login again - switching between the two demo
     * clients, or simply pressing the sign-in button twice. Clear the session and let the flow begin
     * from a clean slate.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!this.authorizationRequestMatcher.matches(request)
                || !(authentication instanceof OAuth2AuthenticationToken)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("Restarting login for [{}]: session already holds an OAuth2 authentication",
                request.getRequestURI());
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        // Same URI, now without an authentication in the way.
        response.sendRedirect(request.getRequestURI());
    }
}
