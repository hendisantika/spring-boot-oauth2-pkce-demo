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
 * Date: 14/09/26
 * Time: 21.10
 */
@Configuration(proxyBeanMethods = false)
public class PaymentApiSecurityConfig {

    /**
     * A resource server for /payments that asks only whether the token is valid. What the token
     * <em>permits</em> depends on the amount and the account in the request body, which no filter
     * can see - so that half is decided in the endpoint, which is where RFC 9396 leaves it.
     */
    @Bean
    @Order(-2)
    public SecurityFilterChain paymentApiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/payments/**")
                .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));
        return http.build();
    }
}
