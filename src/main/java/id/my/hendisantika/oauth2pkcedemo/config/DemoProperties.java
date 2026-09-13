package id.my.hendisantika.oauth2pkcedemo.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 12.56
 */
@ConfigurationProperties(prefix = "app")
public record DemoProperties(String issuerUri, Client client, List<DemoUser> demoUsers) {

    public record Client(String registrationId,
                         String clientId,
                         String clientName,
                         @DefaultValue({"openid", "profile", "email"}) List<String> scopes) {
    }

    public record DemoUser(String username,
                           String password,
                           String fullName,
                           String email,
                           List<String> authorities) {
    }
}
