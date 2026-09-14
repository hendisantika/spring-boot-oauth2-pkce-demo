package id.my.hendisantika.oauth2pkcedemo.security;

import com.nimbusds.jwt.JWTParser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 23.05
 */
@Slf4j
@RequiredArgsConstructor
public final class DpopNonceRequiredFilter extends OncePerRequestFilter {

    public static final String DPOP_HEADER = "DPoP";
    public static final String NONCE_HEADER = "DPoP-Nonce";
    public static final String USE_DPOP_NONCE = "use_dpop_nonce";

    private final DpopNonceStore nonceStore;

    /**
     * RFC 9449 section 9. A resource server may insist that every proof carry a nonce it issued,
     * which stops a proof made in advance - or captured once - from being usable later. A request
     * without an acceptable nonce is answered with {@code 401}, the error
     * {@code use_dpop_nonce}, and a nonce to use next time; the client makes a new proof and
     * repeats the request.
     * <p>
     * Spring Security has none of this: neither {@code use_dpop_nonce} nor {@code DPoP-Nonce}
     * appears anywhere in its resource server, and the DPoP proof verifier does not look at a
     * {@code nonce} claim. Everything here is this filter's doing.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String proof = request.getHeader(DPOP_HEADER);
        if (!StringUtils.hasText(proof)) {
            // No proof at all is not this filter's business: Spring answers that on its own, and
            // answering it here would hide what it says.
            filterChain.doFilter(request, response);
            return;
        }

        String nonce = nonceOf(proof);
        if (nonceStore.spend(nonce)) {
            // Accepted, and the next request needs a different one - so a fresh nonce goes back with
            // the answer rather than only with a refusal.
            response.setHeader(NONCE_HEADER, nonceStore.issue());
            filterChain.doFilter(request, response);
            return;
        }

        challenge(response, nonce == null
                ? "The proof carries no nonce"
                : "The proof carries a nonce this server will not accept");
    }

    private void challenge(HttpServletResponse response, String description) throws IOException {
        String nonce = nonceStore.issue();
        log.debug("Challenging for a DPoP nonce: {}", description);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setHeader(NONCE_HEADER, nonce);
        response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "DPoP error=\"" + USE_DPOP_NONCE + "\", "
                + "error_description=\"" + description + "\", algs=\"ES256\"");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + USE_DPOP_NONCE + "\"}");
    }

    /**
     * Reads the claim without checking the signature, which is safe here because it decides only
     * whether to ask for a nonce. A proof that survives this still has to satisfy Spring's own
     * verification afterwards - the signature, the method, the URI, the token hash - or the request
     * is refused anyway.
     */
    private static String nonceOf(String proof) {
        try {
            Object nonce = JWTParser.parse(proof).getJWTClaimsSet().getClaim("nonce");
            return nonce == null ? null : String.valueOf(nonce);
        } catch (Exception ex) {
            return null;
        }
    }
}
