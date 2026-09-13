package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.40
 */
public final class DeviceClientAuthenticationConverter implements AuthenticationConverter {

    private final RequestMatcher deviceAuthorizationRequestMatcher;
    private final RequestMatcher tokenRequestMatcher;

    public DeviceClientAuthenticationConverter(String deviceAuthorizationEndpointUri, String tokenEndpointUri) {
        PathPatternRequestMatcher.Builder matchers = PathPatternRequestMatcher.withDefaults();
        this.deviceAuthorizationRequestMatcher = matchers.matcher(HttpMethod.POST, deviceAuthorizationEndpointUri);
        this.tokenRequestMatcher = matchers.matcher(HttpMethod.POST, tokenEndpointUri);
    }

    /**
     * Recognises a device identifying itself with nothing but its {@code client_id}, on the two
     * requests the device grant makes: asking for codes, and redeeming the device code.
     * <p>
     * Spring Authorization Server ships no client authentication for either case. Its
     * {@code PublicClientAuthenticationConverter} returns early unless the request is a PKCE token
     * request, yet both endpoints insist on an authenticated client - so without this, a public
     * device client is bounced to the login page instead of being served JSON.
     */
    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!isDeviceAuthorizationRequest(request) && !isDeviceCodeTokenRequest(request)) {
            return null;
        }
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String[] clientIds = request.getParameterValues(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId) || clientIds == null || clientIds.length != 1) {
            return null;
        }
        return new DeviceClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null, Map.of());
    }

    private boolean isDeviceAuthorizationRequest(HttpServletRequest request) {
        return this.deviceAuthorizationRequestMatcher.matches(request);
    }

    private boolean isDeviceCodeTokenRequest(HttpServletRequest request) {
        return this.tokenRequestMatcher.matches(request)
                && AuthorizationGrantType.DEVICE_CODE.getValue()
                .equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE));
    }
}
