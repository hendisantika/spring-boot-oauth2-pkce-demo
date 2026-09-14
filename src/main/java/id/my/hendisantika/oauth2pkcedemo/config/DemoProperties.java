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
public record DemoProperties(String issuerUri,
                             Client client,
                             Client confidentialClient,
                             Client assertionClient,
                             Client mtlsClient,
                             Client exchangeClient,
                             Client cibaClient,
                             Client fapiClient,
                             Client codeBindingClient,
                             Client mixUpClient,
                             Client registrarClient,
                             Client relayClient,
                             Client mtlsRefreshClient,
                             Client freshnessClient,
                             Client silentClient,
                             Client requestUriClient,
                             Client rarClient,
                             Client dpopNonceClient,
                             Client jarmClient,
                             Client jarmEcClient,
                             Client jarmNoneClient,
                             Client jarmEncryptedClient,
                             Client jarmGcmClient,
                             Client jarmUnsupportedEncClient,
                             Client jarPsClient,
                             List<DemoUser> demoUsers) {

    /**
     * @param clientSecret {@code null} marks a public client, which authenticates with nothing but
     *                     its client id and a PKCE code verifier.
     */
    public record Client(String registrationId,
                         String clientId,
                         String clientSecret,
                         String clientName,
                         @DefaultValue({"openid", "profile", "email"}) List<String> scopes) {

        public boolean isPublic() {
            return clientSecret == null || clientSecret.isBlank();
        }
    }

    public record DemoUser(String username,
                           String password,
                           String fullName,
                           String email,
                           List<String> authorities) {
    }
}
