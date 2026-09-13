package id.my.hendisantika.oauth2pkcedemo.config;

import id.my.hendisantika.oauth2pkcedemo.security.ClientAssertionKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 14.42
 */
@Configuration(proxyBeanMethods = false)
public class ClientAssertionKeyConfig {

    /**
     * Generated per boot, like the server's signing key. A real client would load this from a
     * keystore and publish the public half at a stable URL.
     */
    @Bean
    public ClientAssertionKey clientAssertionKey() {
        return ClientAssertionKey.generate();
    }
}
