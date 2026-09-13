package id.my.hendisantika.oauth2pkcedemo.security;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 13.40
 */
public record StepUpChallengeRun(List<ResourceCallAttempt> attempts) implements Serializable {

    public static StepUpChallengeRun empty() {
        return new StepUpChallengeRun(new ArrayList<>());
    }

    public StepUpChallengeRun with(ResourceCallAttempt attempt) {
        List<ResourceCallAttempt> next = new ArrayList<>(attempts);
        next.add(attempt);
        return new StepUpChallengeRun(next);
    }

    /** The challenge the client is currently meant to act on, if the last call produced one. */
    public StepUpChallenge pendingChallenge() {
        if (attempts.isEmpty()) {
            return null;
        }
        ResourceCallAttempt last = attempts.get(attempts.size() - 1);
        return last.challenge() != null && last.challenge().asksForStrongerAuthentication()
                ? last.challenge() : null;
    }

    public boolean succeeded() {
        return attempts.stream().anyMatch(ResourceCallAttempt::isSuccess);
    }
}
