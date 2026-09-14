package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.security.AuthorizationDetailsDecision;
import id.my.hendisantika.oauth2pkcedemo.security.PaymentAuthorizer;
import id.my.hendisantika.oauth2pkcedemo.security.PaymentInstruction;
import id.my.hendisantika.oauth2pkcedemo.security.RichAuthorizationRequestValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 21.10
 */
@Slf4j
@RestController
public class PaymentApiController {

    public static final String PAYMENTS_URI = "/payments";

    /**
     * The operation the grant was about. A scope could only have said "payments"; the token here
     * says which payment was approved, so this compares the instruction against it rather than
     * against a category.
     */
    @PostMapping(value = PAYMENTS_URI, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> pay(@AuthenticationPrincipal Jwt jwt,
                                                   @RequestParam("amount") BigDecimal amount,
                                                   @RequestParam("currency") String currency,
                                                   @RequestParam("creditor_iban") String creditorIban) {
        PaymentInstruction payment = new PaymentInstruction(amount, currency, creditorIban);
        AuthorizationDetailsDecision decision = PaymentAuthorizer.decide(
                jwt.getClaim(RichAuthorizationRequestValidator.AUTHORIZATION_DETAILS), payment);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("payment", payment.describe());
        body.put("sub", jwt.getSubject());
        body.put("reason", decision.reason());
        if (decision.allowed()) {
            body.put("status", "accepted");
            return ResponseEntity.ok(body);
        }

        // RFC 9396 registers no error of its own for this, so the nearest existing one is used:
        // RFC 6750 section 3.1's insufficient_scope, which is what a bearer token that does not
        // cover the operation has always been answered with.
        body.put("status", "refused");
        log.debug("Refused {}: {}", payment.describe(), decision.reason());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"insufficient_scope\", "
                        + "error_description=\"" + decision.reason() + "\"")
                .body(body);
    }
}
