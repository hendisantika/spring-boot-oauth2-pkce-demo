package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 14.24
 */
public record DpopDemoResult(String thumbprint,
                             String publicJwk,
                             String tokenType,
                             String accessToken,
                             Map<String, Object> accessTokenClaims,
                             String proofHeader,
                             Map<String, Object> proofClaims,
                             List<ApiCall> calls) implements Serializable {

    /**
     * One attempt at the protected resource, described so the page can show why it was or was not
     * allowed.
     */
    public record ApiCall(String label,
                          String description,
                          int statusCode,
                          String body) implements Serializable {

        public boolean isSuccess() {
            return statusCode == 200;
        }
    }
}
