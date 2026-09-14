package id.my.hendisantika.oauth2pkcedemo.security;

import lombok.extern.slf4j.Slf4j;

import java.math.BigDecimal;
import java.util.List;
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
public final class PaymentAuthorizer {

    public static final String PAYMENT_INITIATION = "payment_initiation";
    public static final String INITIATE = "initiate";

    private PaymentAuthorizer() {
    }

    /**
     * RFC 9396 section 7: the token carries what was granted, and it is the resource server that has
     * to hold the operation against it. A scope would say "payments"; this says which payment, of how
     * much, to whom - so the comparison is arithmetic rather than a category match.
     *
     * @param grantedDetails the {@code authorization_details} claim, as it comes off the token
     */
    public static AuthorizationDetailsDecision decide(Object grantedDetails, PaymentInstruction payment) {
        List<Map<String, Object>> details = asDetails(grantedDetails);
        if (details.isEmpty()) {
            return AuthorizationDetailsDecision.refused(
                    "The token carries no authorization_details, so nothing here was ever approved");
        }

        for (Map<String, Object> detail : details) {
            AuthorizationDetailsDecision decision = against(detail, payment);
            if (decision.allowed()) {
                return decision;
            }
            log.debug("Payment {} not covered: {}", payment.describe(), decision.reason());
        }
        // The first refusal is the informative one: every detail is checked, and the reason given is
        // the one from the detail of the right type, if there was one.
        return details.stream()
                .filter(detail -> PAYMENT_INITIATION.equals(detail.get("type")))
                .findFirst()
                .map(detail -> against(detail, payment))
                .orElseGet(() -> AuthorizationDetailsDecision.refused(
                        "Nothing of type " + PAYMENT_INITIATION + " was approved"));
    }

    private static AuthorizationDetailsDecision against(Map<String, Object> detail,
                                                        PaymentInstruction payment) {
        if (!PAYMENT_INITIATION.equals(detail.get("type"))) {
            return AuthorizationDetailsDecision.refused(
                    "Nothing of type " + PAYMENT_INITIATION + " was approved");
        }
        if (detail.get("actions") instanceof List<?> actions
                && !actions.isEmpty() && !actions.contains(INITIATE)) {
            return AuthorizationDetailsDecision.refused(
                    "The grant does not include the " + INITIATE + " action");
        }

        BigDecimal grantedAmount = amountOf(detail);
        String grantedCurrency = currencyOf(detail);
        if (grantedAmount == null || grantedCurrency == null) {
            return AuthorizationDetailsDecision.refused(
                    "The granted detail names no amount, so no payment is covered by it");
        }
        if (!grantedCurrency.equals(payment.currency())) {
            return AuthorizationDetailsDecision.refused(
                    "The grant is in " + grantedCurrency + ", not " + payment.currency());
        }
        if (payment.amount().compareTo(grantedAmount) > 0) {
            return AuthorizationDetailsDecision.refused(
                    "The grant covers " + grantedAmount.toPlainString() + " " + grantedCurrency
                            + ", and this asks for " + payment.amount().toPlainString());
        }

        String grantedIban = ibanOf(detail);
        if (grantedIban != null && !grantedIban.equals(payment.creditorIban())) {
            return AuthorizationDetailsDecision.refused(
                    "The grant names a different creditor account");
        }
        return AuthorizationDetailsDecision.allowed(
                "Within the " + grantedAmount.toPlainString() + " " + grantedCurrency + " approved"
                        + (grantedIban == null ? "" : " for that account"));
    }

    private static BigDecimal amountOf(Map<String, Object> detail) {
        if (detail.get("instructedAmount") instanceof Map<?, ?> amount
                && amount.get("amount") != null) {
            try {
                return new BigDecimal(String.valueOf(amount.get("amount")));
            } catch (NumberFormatException ex) {
                return null;
            }
        }
        return null;
    }

    private static String currencyOf(Map<String, Object> detail) {
        return detail.get("instructedAmount") instanceof Map<?, ?> amount
                && amount.get("currency") != null ? String.valueOf(amount.get("currency")) : null;
    }

    private static String ibanOf(Map<String, Object> detail) {
        return detail.get("creditorAccount") instanceof Map<?, ?> account
                && account.get("iban") != null ? String.valueOf(account.get("iban")) : null;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> asDetails(Object claim) {
        if (claim instanceof List<?> list) {
            return list.stream()
                    .filter(Map.class::isInstance)
                    .map(entry -> (Map<String, Object>) entry)
                    .toList();
        }
        return List.of();
    }
}
