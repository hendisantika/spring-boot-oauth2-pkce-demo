package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 15/09/26
 * Time: 23.40
 */
public record RequestObjectAttempt(String label,
                                   String description,
                                   int parts,
                                   boolean encrypted,
                                   List<String> readableWithoutAKey,
                                   boolean accepted,
                                   String outcome) implements Serializable {

    /** Three parts is a signed request object; five means it was encrypted around one. */
    public String shape() {
        return parts == 5 ? "a JWE" : (parts == 3 ? "a JWS" : parts + " parts");
    }
}
