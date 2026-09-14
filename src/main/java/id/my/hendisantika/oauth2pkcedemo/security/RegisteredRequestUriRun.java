package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 18/09/26
 * Time: 09.40
 */
public record RegisteredRequestUriRun(String listedClientId,
                                      String unlistedClientId,
                                      List<String> requested,
                                      Object echoed,
                                      List<String> stored,
                                      List<RegisteredRequestUriAttempt> attempts,
                                      Instant ranAt) implements Serializable {

    /** RFC 7591 section 3.2.1: what the server holds is what the response describes. */
    public boolean echoedAsAList() {
        return echoed instanceof List<?> list && list.size() == requested.size();
    }

    /** And what it holds is what was asked for, in the same order. */
    public boolean storedWhatWasRequested() {
        return stored.equals(requested);
    }

    /** Only the registered URL was fetched; everything else was refused before anything left. */
    public long accepted() {
        return attempts.stream().filter(RegisteredRequestUriAttempt::accepted).count();
    }

    /** Nothing off the list was acted on, which is what registering a list is for. */
    public boolean nothingOffTheListWasUsed() {
        return attempts.stream()
                .noneMatch(attempt -> attempt.accepted() && !attempt.onTheList());
    }
}
