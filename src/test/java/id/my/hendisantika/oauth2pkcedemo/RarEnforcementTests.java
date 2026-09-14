package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.controller.PaymentApiController;
import id.my.hendisantika.oauth2pkcedemo.security.AuthorizationDetailsDecision;
import id.my.hendisantika.oauth2pkcedemo.security.PaymentAuthorizer;
import id.my.hendisantika.oauth2pkcedemo.security.PaymentInstruction;
import id.my.hendisantika.oauth2pkcedemo.security.RichAuthorizationRequestValidator;
import id.my.hendisantika.oauth2pkcedemo.service.RarEnforcementService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 14/09/26
 * Time: 21.10
 */
@SpringBootTest
class RarEnforcementTests extends AbstractMySqlIntegrationTest {

    private static final Map<String, Object> GRANTED = Map.of(
            "type", PaymentAuthorizer.PAYMENT_INITIATION,
            "actions", List.of(PaymentAuthorizer.INITIATE),
            "instructedAmount", Map.of("currency", "EUR", "amount", "25.00"),
            "creditorAccount", Map.of("iban", RarEnforcementService.APPROVED_IBAN));

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private DemoProperties properties;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    /** The comparison a scope could never express: how much, and to whom. */
    @Test
    void anInstructionWithinTheGrantIsAllowed() {
        AuthorizationDetailsDecision decision = PaymentAuthorizer.decide(List.of(GRANTED),
                payment("25.00", "EUR", RarEnforcementService.APPROVED_IBAN));

        assertThat(decision.allowed()).isTrue();
        // Less is still within it - the grant is a ceiling, not an instruction.
        assertThat(PaymentAuthorizer.decide(List.of(GRANTED),
                payment("1.00", "EUR", RarEnforcementService.APPROVED_IBAN)).allowed()).isTrue();
    }

    @Test
    void everyWayOfExceedingTheGrantIsRefused() {
        assertThat(PaymentAuthorizer.decide(List.of(GRANTED),
                payment("25.01", "EUR", RarEnforcementService.APPROVED_IBAN)).reason())
                .contains("covers 25.00 EUR");
        assertThat(PaymentAuthorizer.decide(List.of(GRANTED),
                payment("25.00", "USD", RarEnforcementService.APPROVED_IBAN)).reason())
                .contains("in EUR");
        assertThat(PaymentAuthorizer.decide(List.of(GRANTED),
                payment("25.00", "EUR", RarEnforcementService.OTHER_IBAN)).reason())
                .contains("different creditor account");
        assertThat(PaymentAuthorizer.decide(List.of(Map.of("type", "account_information")),
                payment("25.00", "EUR", RarEnforcementService.APPROVED_IBAN)).reason())
                .contains("Nothing of type payment_initiation");
    }

    /** Absent details mean nothing was granted, not that there is nothing to check. */
    @Test
    void aTokenWithNoDetailsGrantsNothing() {
        assertThat(PaymentAuthorizer.decide(null,
                payment("25.00", "EUR", RarEnforcementService.APPROVED_IBAN)).allowed()).isFalse();
        assertThat(PaymentAuthorizer.decide(List.of(),
                payment("25.00", "EUR", RarEnforcementService.APPROVED_IBAN)).reason())
                .contains("no authorization_details");
    }

    @Test
    void theEndpointAcceptsAPaymentTheTokenCovers() throws Exception {
        MvcResult result = mockMvc().perform(payRequest("25.00", RarEnforcementService.APPROVED_IBAN)
                        .with(jwt().jwt(builder -> builder.subject("hendi")
                                .claim(RichAuthorizationRequestValidator.AUTHORIZATION_DETAILS,
                                        List.of(GRANTED)))))
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getResponse().getContentAsString()).contains("\"accepted\"");
        assertThat(result.getResponse().getHeader(HttpHeaders.WWW_AUTHENTICATE)).isNull();
    }

    /**
     * RFC 9396 registers no error for an operation outside the grant, so the nearest existing one is
     * used - and the description says what was actually wrong.
     */
    @Test
    void theEndpointRefusesAnOverspendWithTheNearestErrorThereIs() throws Exception {
        MvcResult result = mockMvc().perform(payRequest("500.00", RarEnforcementService.APPROVED_IBAN)
                        .with(jwt().jwt(builder -> builder.subject("hendi")
                                .claim(RichAuthorizationRequestValidator.AUTHORIZATION_DETAILS,
                                        List.of(GRANTED)))))
                .andExpect(status().isForbidden())
                .andReturn();

        assertThat(result.getResponse().getHeader(HttpHeaders.WWW_AUTHENTICATE))
                .contains("insufficient_scope")
                .contains("covers 25.00 EUR");
    }

    @Test
    void theEndpointRefusesAnOrdinaryTokenAltogether() throws Exception {
        mockMvc().perform(payRequest("25.00", RarEnforcementService.APPROVED_IBAN)
                        .with(jwt().jwt(builder -> builder.subject("hendi"))))
                .andExpect(status().isForbidden());
    }

    /** A grant describes what was authorized, not how many times it may happen. */
    @Test
    void theGrantIsNotConsumedByUsingIt() throws Exception {
        for (int attempt = 0; attempt < 2; attempt++) {
            mockMvc().perform(payRequest("25.00", RarEnforcementService.APPROVED_IBAN)
                            .with(jwt().jwt(builder -> builder.subject("hendi")
                                    .claim(RichAuthorizationRequestValidator.AUTHORIZATION_DETAILS,
                                            List.of(GRANTED)))))
                    .andExpect(status().isOk());
        }
    }

    @Test
    void theProbeClientIsConfidentialAndAsksForNoConsent() {
        RegisteredClient client =
                registeredClientRepository.findByClientId(properties.rarClient().clientId());

        assertThat(client).isNotNull();
        assertThat(client.getClientAuthenticationMethods())
                .containsExactly(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getClientSettings().isRequireAuthorizationConsent()).isFalse();
    }

    @Test
    void thePageIsReachableWithoutSigningIn() throws Exception {
        mockMvc().perform(get("/rar-enforcement")).andExpect(status().isOk());
    }

    private static MockHttpServletRequestBuilder payRequest(String amount, String iban) {
        return post(PaymentApiController.PAYMENTS_URI)
                .param("amount", amount)
                .param("currency", "EUR")
                .param("creditor_iban", iban);
    }

    private static PaymentInstruction payment(String amount, String currency, String iban) {
        return new PaymentInstruction(new BigDecimal(amount), currency, iban);
    }
}
