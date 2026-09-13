package id.my.hendisantika.oauth2pkcedemo.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

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
public final class CibaAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    /** OpenID Connect CIBA Core 1.0 section 10.3. */
    public static final AuthorizationGrantType CIBA_GRANT_TYPE =
            new AuthorizationGrantType("urn:openid:params:grant-type:ciba");

    private final String authReqId;

    public CibaAuthenticationToken(String authReqId, Authentication clientPrincipal,
                                   Map<String, Object> additionalParameters) {
        super(CIBA_GRANT_TYPE, clientPrincipal, additionalParameters);
        this.authReqId = authReqId;
    }

    public String getAuthReqId() {
        return this.authReqId;
    }
}
