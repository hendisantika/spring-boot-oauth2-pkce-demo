package id.my.hendisantika.oauth2pkcedemo.service;

import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 16.52
 */
@Slf4j
@Service
public class StepUpService {

    static final String CODE_ATTRIBUTE = "stepup.code";

    private final SecureRandom random = new SecureRandom();

    /**
     * Issues the one-time code for the second factor. A real deployment sends this to a device the
     * user already holds; the demo puts it on screen, which is the one thing here that is not
     * faithful.
     */
    public String issueCode(HttpSession session) {
        String code = String.format("%06d", random.nextInt(1_000_000));
        session.setAttribute(CODE_ATTRIBUTE, code);
        return code;
    }

    public String currentCode(HttpSession session) {
        return (String) session.getAttribute(CODE_ATTRIBUTE);
    }

    /**
     * Adds the second factor to the session rather than replacing what is there. That is what makes
     * it a step-up: the password factor stays, and {@code amr} ends up listing both.
     *
     * @return whether the code was right
     */
    public boolean verify(HttpSession session, String submittedCode) {
        String expected = currentCode(session);
        if (expected == null || !expected.equals(submittedCode)) {
            return false;
        }
        session.removeAttribute(CODE_ATTRIBUTE);

        SecurityContext context = SecurityContextHolder.getContext();
        Authentication current = context.getAuthentication();

        Set<GrantedAuthority> authorities = new LinkedHashSet<>(current.getAuthorities());
        authorities.add(FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.OTT_AUTHORITY));

        UsernamePasswordAuthenticationToken steppedUp = UsernamePasswordAuthenticationToken
                .authenticated(current.getPrincipal(), current.getCredentials(), authorities);
        steppedUp.setDetails(current.getDetails());
        context.setAuthentication(steppedUp);
        // Written back explicitly so the upgraded authentication survives the redirect.
        session.setAttribute("SPRING_SECURITY_CONTEXT", context);

        log.debug("Stepped up [{}] to a second factor", current.getName());
        return true;
    }
}
