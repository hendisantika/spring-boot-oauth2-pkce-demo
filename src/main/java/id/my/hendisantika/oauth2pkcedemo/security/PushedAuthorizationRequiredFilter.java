package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
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
 * Date: 16/09/26
 * Time: 22.40
 */
@Slf4j
public final class PushedAuthorizationRequiredFilter extends OncePerRequestFilter {

    /**
     * RFC 9126 section 6: "Boolean parameter indicating whether the only means of initiating an
     * authorization request the client is allowed to use is PAR. If omitted, the default value is
     * false." Spring Authorization Server has no setting for it, so it travels as a custom one.
     */
    public static final String REQUIRE_PAR_SETTING = "settings.client.require-pushed-authorization-requests";

    private final RequestMatcher authorizationEndpointMatcher;
    private final RegisteredClientRepository registeredClients;

    /** RFC 9126 section 5, the server-wide half, which outranks what any one client registered. */
    private final PushedAuthorizationPolicy policy;

    public PushedAuthorizationRequiredFilter(String authorizationEndpointUri,
                                             RegisteredClientRepository registeredClients,
                                             PushedAuthorizationPolicy policy) {
        this.authorizationEndpointMatcher =
                PathPatternRequestMatcher.withDefaults().matcher(authorizationEndpointUri);
        this.registeredClients = registeredClients;
        this.policy = policy;
    }

    /**
     * A client that registered {@code require_pushed_authorization_requests} has one way to start an
     * authorization request, and a query string full of parameters is not it.
     * <p>
     * Only a GET is judged, for the same reason the request object filter judges only a GET: the
     * consent screen posts back to this endpoint to continue a request that was already made and
     * already checked.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!this.authorizationEndpointMatcher.matches(request) || !"GET".equals(request.getMethod())
                || StringUtils.hasText(request.getParameter(OAuth2ParameterNames.REQUEST_URI))) {
            filterChain.doFilter(request, response);
            return;
        }

        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String refusal = whyPushingIsRequired(clientId);
        if (refusal == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // Presence of the parameter is all this filter judges. Whether the reference is one this
        // server issued, is still alive, and belongs to this client is the authorization server's
        // own check, and it runs immediately after.
        log.debug("Rejecting an authorization request from [{}] that did not come through PAR: {}",
                clientId, refusal);
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + OAuth2ErrorCodes.INVALID_REQUEST
                + "\",\"error_description\":\"" + refusal + "\"}");
    }

    /**
     * RFC 9126 defines this twice. The server metadata value refuses a request that did not come
     * through the pushed endpoint from everybody; the client metadata value refuses one from a
     * single client. The server's is checked first because it is the one that cannot be talked out
     * of by a registration.
     *
     * @return why the request cannot proceed, or null where it can
     */
    private String whyPushingIsRequired(String clientId) {
        if (this.policy.requirePushedRequests()) {
            return "This server accepts authorization request data only via PAR";
        }
        RegisteredClient client = clientId == null ? null
                : this.registeredClients.findByClientId(clientId);
        if (client == null) {
            return null;
        }
        Object setting = client.getClientSettings().getSetting(REQUIRE_PAR_SETTING);
        return setting != null && Boolean.parseBoolean(String.valueOf(setting))
                ? "This client registered require_pushed_authorization_requests"
                : null;
    }
}
