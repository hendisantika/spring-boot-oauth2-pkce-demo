package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
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
 * Date: 13/09/26
 * Time: 16.52
 */
@Slf4j
public final class StepUpRequiredFilter extends OncePerRequestFilter {

    public static final String ACR_VALUES = "acr_values";
    public static final String STEP_UP_URI = "/stepup/verify";

    private final RequestMatcher authorizationEndpointMatcher;
    private final RequestCache requestCache = new HttpSessionRequestCache();

    public StepUpRequiredFilter(String authorizationEndpointUri) {
        this.authorizationEndpointMatcher =
                PathPatternRequestMatcher.withDefaults().matcher(authorizationEndpointUri);
    }

    /**
     * Enforces {@code acr_values} on the authorization request. Spring Authorization Server ignores
     * the parameter, so without this a client could ask for a stronger authentication and be handed
     * a token that silently says otherwise.
     * <p>
     * When the session falls short, the request is saved and the user sent to collect the missing
     * factor — the authorization endpoint prompting, which is exactly what it is for.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String requestedAcr = request.getParameter(ACR_VALUES);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!this.authorizationEndpointMatcher.matches(request)
                || !StringUtils.hasText(requestedAcr)
                || authentication == null
                || !authentication.isAuthenticated()
                // Not signed in at all yet: let the usual login handle it first.
                || AuthenticationContextLevel.satisfies(authentication, requestedAcr)) {
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("acr_values={} not met by {}; stepping up",
                requestedAcr, AuthenticationContextLevel.acrOf(authentication));
        this.requestCache.saveRequest(request, response);
        response.sendRedirect(request.getContextPath() + STEP_UP_URI);
    }
}
