package id.my.hendisantika.oauth2pkcedemo.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 16.10
 */
public final class CibaAuthenticationConverter implements AuthenticationConverter {

    public static final String AUTH_REQ_ID = "auth_req_id";

    /**
     * Recognises the CIBA grant at the token endpoint. Spring Authorization Server knows nothing
     * about it, so without this the request is answered with {@code unsupported_grant_type}.
     */
    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!CibaAuthenticationToken.CIBA_GRANT_TYPE.getValue().equals(grantType)) {
            return null;
        }

        String authReqId = request.getParameter(AUTH_REQ_ID);
        if (!StringUtils.hasText(authReqId)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }
        // The client has already been authenticated by the time the token endpoint runs converters.
        return new CibaAuthenticationToken(authReqId, SecurityContextHolder.getContext().getAuthentication(),
                Map.of());
    }
}
