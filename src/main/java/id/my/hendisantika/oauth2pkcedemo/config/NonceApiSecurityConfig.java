package id.my.hendisantika.oauth2pkcedemo.config;

import id.my.hendisantika.oauth2pkcedemo.security.DpopNonceRequiredFilter;
import id.my.hendisantika.oauth2pkcedemo.security.DpopNonceStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 23.05
 */
@Configuration(proxyBeanMethods = false)
public class NonceApiSecurityConfig {

    /**
     * The same DPoP-only resource server as /api/**, with one addition: every proof must also carry
     * a nonce this server issued. Kept on its own path so the
     * <a href="https://datatracker.ietf.org/doc/html/rfc9449">DPoP page</a> still shows the ordinary
     * arrangement, where a proof is enough by itself.
     */
    @Bean
    @Order(-3)
    public SecurityFilterChain nonceApiSecurityFilterChain(HttpSecurity http,
                                                           DpopNonceStore nonceStore) throws Exception {
        http
                .securityMatcher("/nonce/**")
                .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults())
                        // Bearer is kept out for the same reason as on /api/**: it would accept a
                        // bound token without ever looking at a proof.
                        .bearerTokenResolver(request -> null)
                        .dPoP(Customizer.withDefaults()))
                // Before the token is authenticated at all: a client that has not been given a nonce
                // yet should be told so, not told its token is bad.
                .addFilterAfter(new DpopNonceRequiredFilter(nonceStore), SecurityContextHolderFilter.class);
        return http.build();
    }
}
