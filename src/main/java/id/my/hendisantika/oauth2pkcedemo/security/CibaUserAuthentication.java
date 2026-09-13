package id.my.hendisantika.oauth2pkcedemo.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 16.10
 */
public final class CibaUserAuthentication extends AbstractAuthenticationToken {

    private final UserDetails user;

    /**
     * Stands in for the end user during token generation. The approval happened on another device
     * minutes ago, so there is no live authentication to carry over - this records who it was for.
     */
    public CibaUserAuthentication(UserDetails user) {
        super(user.getAuthorities());
        this.user = user;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return this.user;
    }

    @Override
    public String getName() {
        return this.user.getUsername();
    }
}
