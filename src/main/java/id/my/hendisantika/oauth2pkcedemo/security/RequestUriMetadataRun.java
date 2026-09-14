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
 * Date: 17/09/26
 * Time: 16.05
 */
public record RequestUriMetadataRun(Map<String, Object> published,
                                    Map<String, Object> defaultsIfOmitted,
                                    List<RequestUriMetadataAttempt> attempts,
                                    Instant ranAt) implements Serializable {

    public long accepted() {
        return attempts.stream().filter(RequestUriMetadataAttempt::accepted).count();
    }

    /**
     * The reason publishing these is worth doing: on both request parameters, the value this server
     * would be taken to hold by saying nothing is the opposite of the one it holds.
     */
    public boolean everyDefaultIsBackwards() {
        return published.entrySet().stream()
                .filter(entry -> defaultsIfOmitted.containsKey(entry.getKey()))
                .filter(entry -> !"require_request_uri_registration".equals(entry.getKey()))
                .allMatch(entry -> !entry.getValue().equals(defaultsIfOmitted.get(entry.getKey())));
    }

    /** RFC 9126 section 5's "regardless": a pushed reference works while the metadata says false. */
    public boolean thePushedReferenceWorkedAnyway() {
        return attempts.stream()
                .anyMatch(attempt -> attempt.accepted()
                        && "request_uri".equals(attempt.parameter())
                        && attempt.value().startsWith("urn:"));
    }
}
