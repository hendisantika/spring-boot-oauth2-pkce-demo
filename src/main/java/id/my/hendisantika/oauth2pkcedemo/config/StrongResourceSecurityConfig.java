package id.my.hendisantika.oauth2pkcedemo.config;

import id.my.hendisantika.oauth2pkcedemo.security.AuthenticationContextLevel;
import id.my.hendisantika.oauth2pkcedemo.security.InsufficientUserAuthenticationHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 13.20
 */
@Configuration(proxyBeanMethods = false)
public class StrongResourceSecurityConfig {

    /** What the endpoint insists on, and how fresh it wants the authentication to be. */
    public static final String REQUIRED_ACR = AuthenticationContextLevel.LOA_2;
    public static final long MAX_AGE_SECONDS = 300;

    /**
     * A resource server for /resource/** that accepts an ordinary bearer token and then looks at how
     * the user behind it authenticated. A valid token is not the question here - the question is
     * whether it was earned with enough factors, which is the only thing RFC 9470 is about.
     */
    @Bean
    @Order(-1)
    public SecurityFilterChain strongResourceSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/resource/**")
                .authorizeHttpRequests(requests -> requests
                        .anyRequest().access((authentication, context) ->
                                new AuthorizationDecision(meetsRequiredAcr(authentication.get()))))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults())
                        // The 401 the client is meant to read, in place of Spring's 403.
                        .accessDeniedHandler(new InsufficientUserAuthenticationHandler(
                                REQUIRED_ACR, MAX_AGE_SECONDS)));
        return http.build();
    }

    /** The acr claim the authorization server put on the token when the user authenticated. */
    private static boolean meetsRequiredAcr(Object authentication) {
        if (!(authentication instanceof JwtAuthenticationToken token)) {
            return false;
        }
        Jwt jwt = token.getToken();
        return REQUIRED_ACR.equals(jwt.getClaimAsString("acr"));
    }
}
