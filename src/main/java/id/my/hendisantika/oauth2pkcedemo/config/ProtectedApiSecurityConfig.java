package id.my.hendisantika.oauth2pkcedemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 14.24
 */
@Configuration(proxyBeanMethods = false)
public class ProtectedApiSecurityConfig {

    /**
     * A resource server for /api/** that accepts <em>only</em> DPoP-bound tokens.
     * <p>
     * Bearer is deliberately not configured alongside: a plain JWT filter would happily accept a
     * DPoP-bound token presented as {@code Authorization: Bearer}, since nothing in it checks
     * {@code cnf.jkt} - and that would quietly undo the binding this endpoint exists to demonstrate.
     */
    @Bean
    @Order(0)
    public SecurityFilterChain protectedApiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**")
                .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(resourceServer -> resourceServer
                        // Needed so the access token itself can be decoded; it also installs the
                        // bearer filter, so the resolver below is what actually keeps Bearer out.
                        .jwt(Customizer.withDefaults())
                        .bearerTokenResolver(request -> null)
                        .dPoP(Customizer.withDefaults()));
        return http.build();
    }
}
