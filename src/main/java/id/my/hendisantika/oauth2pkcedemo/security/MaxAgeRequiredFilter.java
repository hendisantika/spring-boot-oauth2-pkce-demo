package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 15.10
 */
@Slf4j
public final class MaxAgeRequiredFilter extends OncePerRequestFilter {

    /**
     * Marks the one authorization request this filter has already sent back. Without it
     * {@code max_age=0} never terminates: the login it forces is itself moments old, the resumed
     * request is judged stale all over again, and the browser bounces between the two forever.
     */
    private static final String ALREADY_FORCED = MaxAgeRequiredFilter.class.getName() + ".forced";

    private final RequestMatcher authorizationEndpointMatcher;
    private final SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();

    public MaxAgeRequiredFilter(String authorizationEndpointUri) {
        this.authorizationEndpointMatcher =
                PathPatternRequestMatcher.withDefaults().matcher(authorizationEndpointUri);
    }

    /**
     * Enforces {@code max_age} on the authorization request. Spring Authorization Server does not
     * recognise the parameter at all - the string appears nowhere in it - so without this a client
     * could ask for a recent authentication and be handed a token saying the user last proved
     * anything hours ago.
     * <p>
     * A session that is too old has its authentication taken away and the same request is sent
     * round again: unauthenticated this time, so the ordinary entry point asks for a password and
     * the authorization resumes afterwards. The <em>session</em> is deliberately left intact - the
     * client's own authorization request, with its state and PKCE verifier, lives there, and
     * invalidating it would strand the callback.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String parameter = request.getParameter(AuthenticationFreshness.MAX_AGE);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Long maxAge = StringUtils.hasText(parameter) ? AuthenticationFreshness.parse(parameter) : null;

        if (!this.authorizationEndpointMatcher.matches(request)
                || maxAge == null
                // prompt=none says the user may not be shown anything, so a stale session cannot be
                // fixed by asking. PromptNoneFilter answers those with login_required instead.
                || PromptNoneFilter.requestsNoInteraction(request)
                || authentication == null
                || !authentication.isAuthenticated()
                // Not signed in yet: the login that is about to happen is as fresh as it gets.
                || AuthenticationFreshness.satisfies(authentication, maxAge)) {
            filterChain.doFilter(request, response);
            return;
        }

        HttpSession session = request.getSession(false);
        String marker = request.getParameter(OAuth2ParameterNames.STATE);
        if (session != null && marker != null && marker.equals(session.getAttribute(ALREADY_FORCED))) {
            // This is the request coming back from the login this filter demanded. The session
            // survives that login - only the authentication was taken away - so the marker is still
            // here to be found.
            session.removeAttribute(ALREADY_FORCED);
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("max_age={} not met by an authentication {}s old; asking again",
                maxAge, AuthenticationFreshness.ageSeconds(authentication));
        request.getSession().setAttribute(ALREADY_FORCED, marker);
        SecurityContextHolder.clearContext();
        this.securityContextRepository.saveContext(
                SecurityContextHolder.createEmptyContext(), request, response);
        String query = request.getQueryString();
        response.sendRedirect(request.getRequestURI() + (query == null ? "" : "?" + query));
    }
}
