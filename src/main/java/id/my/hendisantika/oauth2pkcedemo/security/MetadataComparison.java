package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 19.12
 */
public record MetadataComparison(int oauthFieldCount,
                                 int oidcFieldCount,
                                 List<String> onlyInOauthDocument,
                                 List<String> onlyInOidcDocument,
                                 List<String> disagreeing) implements Serializable {

    /**
     * Two documents describing one server. Where they overlap they have to say the same thing, or a
     * client's behaviour depends on which one it happened to fetch.
     */
    public boolean consistent() {
        return disagreeing.isEmpty();
    }
}
