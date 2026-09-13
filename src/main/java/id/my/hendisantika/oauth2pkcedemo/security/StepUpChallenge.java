package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 13.20
 */
public record StepUpChallenge(String scheme,
                              String error,
                              String errorDescription,
                              String acrValues,
                              String maxAge,
                              String raw) implements Serializable {

    /** RFC 9470 section 3 names these two alongside the error; either may be absent. */
    public static final String INSUFFICIENT_USER_AUTHENTICATION = "insufficient_user_authentication";

    private static final Pattern PARAMETER = Pattern.compile("(\\w+)=\"([^\"]*)\"");

    /**
     * Reads a {@code WWW-Authenticate} header the way a client would: the scheme, then the quoted
     * parameters. A client that does not read this has no way to know what went wrong - the status
     * alone says only that the token was not enough.
     */
    public static StepUpChallenge parse(String header) {
        if (header == null || header.isBlank()) {
            return null;
        }
        String scheme = header.split("\\s", 2)[0];
        Map<String, String> parameters = new LinkedHashMap<>();
        Matcher matcher = PARAMETER.matcher(header);
        while (matcher.find()) {
            parameters.put(matcher.group(1), matcher.group(2));
        }
        return new StepUpChallenge(scheme, parameters.get("error"),
                parameters.get("error_description"), parameters.get("acr_values"),
                parameters.get("max_age"), header);
    }

    /** Whether this is the challenge that tells a client to send the user back, not to give up. */
    public boolean asksForStrongerAuthentication() {
        return INSUFFICIENT_USER_AUTHENTICATION.equals(error);
    }
}
