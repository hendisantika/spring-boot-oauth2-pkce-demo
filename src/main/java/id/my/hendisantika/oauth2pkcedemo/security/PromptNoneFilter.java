package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 17.20
 */
@Slf4j
public final class PromptNoneFilter extends OncePerRequestFilter {

    public static final String PROMPT = "prompt";
    public static final String NONE = "none";
    public static final String LOGIN_REQUIRED = "login_required";

    private final RequestMatcher authorizationEndpointMatcher;
    private final RegisteredClientRepository registeredClientRepository;
    private final String issuerUri;

    public PromptNoneFilter(String authorizationEndpointUri,
                            RegisteredClientRepository registeredClientRepository, String issuerUri) {
        this.authorizationEndpointMatcher =
                PathPatternRequestMatcher.withDefaults().matcher(authorizationEndpointUri);
        this.registeredClientRepository = registeredClientRepository;
        this.issuerUri = issuerUri;
    }

    /**
     * Whether a request has said that nothing may be shown to the user. Read by the filters that
     * would otherwise put a screen in front of them.
     */
    public static boolean requestsNoInteraction(HttpServletRequest request) {
        return promptValues(request).contains(NONE);
    }

    private static List<String> promptValues(HttpServletRequest request) {
        String prompt = request.getParameter(PROMPT);
        return StringUtils.hasText(prompt) ? Arrays.asList(prompt.trim().split("\\s+")) : List.of();
    }

    /**
     * OpenID Connect Core 3.1.2.1: with {@code prompt=none} the authorization server must not show
     * the user anything, and answers {@code login_required} instead of asking them to sign in.
     * <p>
     * Spring Authorization Server implements that - and never gets to run it. Its endpoints are
     * behind {@code anyRequest().authenticated()} with a login entry point, as in its own sample, so
     * an unauthenticated request is redirected to the login page several filters earlier: the one
     * thing the parameter forbids. This answers those requests itself, and leaves everything else -
     * the consent case, the success case, a request that combines {@code none} with another prompt -
     * to the server, which handles them correctly.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        List<String> prompts = promptValues(request);
        if (!this.authorizationEndpointMatcher.matches(request)
                || !prompts.contains(NONE)
                // none with anything else is a malformed request, and the server says so itself.
                || prompts.size() > 1) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String reason = reasonToRefuse(request, authentication);
        String redirectUri = validatedRedirectUri(request);
        if (reason == null || redirectUri == null) {
            // Either nothing is in the way, or the request is too broken to answer at its own
            // redirect URI - which is the server's job to report, not this filter's.
            filterChain.doFilter(request, response);
            return;
        }

        log.debug("prompt=none refused: {}", reason);
        UriComponentsBuilder error = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam(OAuth2ParameterNames.ERROR, LOGIN_REQUIRED)
                .queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, reason)
                .queryParam("iss", issuerUri);
        String state = request.getParameter(OAuth2ParameterNames.STATE);
        if (StringUtils.hasText(state)) {
            error.queryParam(OAuth2ParameterNames.STATE, state);
        }
        response.sendRedirect(error.build().encode(StandardCharsets.UTF_8).toUriString());
    }

    /** The two cases that would need the user, described the way the page will quote them. */
    private static String reasonToRefuse(HttpServletRequest request, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return "There is no session to authenticate this request";
        }
        Long maxAge = AuthenticationFreshness.parse(
                String.valueOf(request.getParameter(AuthenticationFreshness.MAX_AGE)));
        if (maxAge != null && !AuthenticationFreshness.satisfies(authentication, maxAge)) {
            // A fresher authentication can only come from the user, and the user may not be asked.
            return "The session is older than max_age and cannot be refreshed without asking";
        }
        return null;
    }

    /**
     * An error may only be sent to a redirect URI the client actually registered - the same rule the
     * authorization server applies, and the reason this cannot simply echo the parameter back.
     */
    private String validatedRedirectUri(HttpServletRequest request) {
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);
        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(redirectUri)) {
            return null;
        }
        RegisteredClient client = this.registeredClientRepository.findByClientId(clientId);
        return client != null && client.getRedirectUris().contains(redirectUri) ? redirectUri : null;
    }
}
