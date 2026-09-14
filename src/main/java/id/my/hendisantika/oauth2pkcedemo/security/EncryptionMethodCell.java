package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 19/09/26
 * Time: 08.20
 */
public record EncryptionMethodCell(String alg,
                                   String enc,
                                   boolean accepted,
                                   String outcome) implements Serializable {

    /** Short enough for a grid cell; the row and column already say which pair this is. */
    public String shortOutcome() {
        if (accepted) {
            return "accepted";
        }
        if (outcome.contains("content is encrypted with")) {
            return "wrong enc";
        }
        if (outcome.contains("is encrypted with")) {
            return "wrong alg";
        }
        if (outcome.contains("does not decrypt")) {
            return "not offered";
        }
        return outcome;
    }
}
