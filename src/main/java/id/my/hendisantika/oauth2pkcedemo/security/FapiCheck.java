package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 17.32
 */
public record FapiCheck(String requirement,
                        String reference,
                        Outcome outcome,
                        String observed) implements Serializable {

    public enum Outcome {
        /** The profile's requirement is met. */
        PASS,
        /** It is not, and this demo says so rather than pretending otherwise. */
        FAIL,
        /** Nothing to check here — the requirement does not apply to this subject. */
        NOT_APPLICABLE
    }

    public static FapiCheck pass(String requirement, String reference, String observed) {
        return new FapiCheck(requirement, reference, Outcome.PASS, observed);
    }

    public static FapiCheck fail(String requirement, String reference, String observed) {
        return new FapiCheck(requirement, reference, Outcome.FAIL, observed);
    }

    public static FapiCheck notApplicable(String requirement, String reference, String observed) {
        return new FapiCheck(requirement, reference, Outcome.NOT_APPLICABLE, observed);
    }

    public static FapiCheck of(boolean satisfied, String requirement, String reference, String observed) {
        return satisfied ? pass(requirement, reference, observed) : fail(requirement, reference, observed);
    }
}
