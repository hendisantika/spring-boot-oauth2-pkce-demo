package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.math.BigDecimal;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 21.10
 */
public record PaymentInstruction(BigDecimal amount,
                                 String currency,
                                 String creditorIban) implements Serializable {

    public String describe() {
        return amount.toPlainString() + " " + currency + " to " + creditorIban;
    }
}
