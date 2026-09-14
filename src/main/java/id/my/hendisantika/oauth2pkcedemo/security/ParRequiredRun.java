package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 16/09/26
 * Time: 22.40
 */
public record ParRequiredRun(String requiredClientId,
                             String ordinaryClientId,
                             String publishedServerWide,
                             List<ParRequiredAttempt> attempts,
                             Instant ranAt) implements Serializable {

    public long accepted() {
        return attempts.stream().filter(ParRequiredAttempt::accepted).count();
    }

    /** The one row that was acted on is the one that went through the pushed endpoint. */
    public boolean onlyThePushedRequestWasActedOn() {
        return attempts.stream()
                .filter(attempt -> attempt.clientRequiresPar() && attempt.accepted())
                .allMatch(attempt -> attempt.carried().contains("request_uri"));
    }

    /** Two checks in sequence, and the page can show which one spoke. */
    public boolean bothCheckersRefusedSomething() {
        return attempts.stream().anyMatch(attempt ->
                ParRequiredAttempt.THIS_FILTER.equals(attempt.refusedBy()))
                && attempts.stream().anyMatch(attempt ->
                ParRequiredAttempt.THE_SERVER.equals(attempt.refusedBy()));
    }
}
