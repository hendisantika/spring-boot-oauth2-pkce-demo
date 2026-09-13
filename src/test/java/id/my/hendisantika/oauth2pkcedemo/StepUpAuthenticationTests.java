package id.my.hendisantika.oauth2pkcedemo;

import id.my.hendisantika.oauth2pkcedemo.security.AuthenticationContextLevel;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 16.52
 */
@SpringBootTest
class StepUpAuthenticationTests extends AbstractMySqlIntegrationTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    private MockMvc mockMvc() {
        return MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    private static Authentication authenticationWith(String... factorAuthorities) {
        List<GrantedAuthority> authorities = new java.util.ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        for (String factor : factorAuthorities) {
            authorities.add(FactorGrantedAuthority.fromAuthority(factor));
        }
        return UsernamePasswordAuthenticationToken.authenticated("hendi", "", authorities);
    }

    @Test
    void onePasswordFactorIsTheLowerLevel() {
        Authentication authentication = authenticationWith(FactorGrantedAuthority.PASSWORD_AUTHORITY);

        assertThat(AuthenticationContextLevel.acrOf(authentication))
                .isEqualTo(AuthenticationContextLevel.LOA_1);
        assertThat(AuthenticationContextLevel.amrOf(authentication)).containsExactly("pwd");
    }

    @Test
    void aSecondFactorRaisesTheLevelAndShowsUpInAmr() {
        Authentication authentication = authenticationWith(
                FactorGrantedAuthority.PASSWORD_AUTHORITY, FactorGrantedAuthority.OTT_AUTHORITY);

        assertThat(AuthenticationContextLevel.acrOf(authentication))
                .isEqualTo(AuthenticationContextLevel.LOA_2);
        assertThat(AuthenticationContextLevel.amrOf(authentication))
                .containsExactlyInAnyOrder("pwd", "otp");
    }

    @Test
    void roleAuthoritiesSayNothingAboutHowSomeoneAuthenticated() {
        // Only FactorGrantedAuthority counts; ROLE_ADMIN is not an authentication method.
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                "hendi", "", List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));

        assertThat(AuthenticationContextLevel.amrOf(authentication)).isEmpty();
        assertThat(AuthenticationContextLevel.acrOf(authentication))
                .isEqualTo(AuthenticationContextLevel.LOA_1);
    }

    @Test
    void aWeakSessionDoesNotSatisfyARequestForTheStrongerLevel() {
        Authentication weak = authenticationWith(FactorGrantedAuthority.PASSWORD_AUTHORITY);
        Authentication strong = authenticationWith(
                FactorGrantedAuthority.PASSWORD_AUTHORITY, FactorGrantedAuthority.OTT_AUTHORITY);

        assertThat(AuthenticationContextLevel.satisfies(weak, AuthenticationContextLevel.LOA_2)).isFalse();
        assertThat(AuthenticationContextLevel.satisfies(strong, AuthenticationContextLevel.LOA_2)).isTrue();
        // The lower level is met by either.
        assertThat(AuthenticationContextLevel.satisfies(weak, AuthenticationContextLevel.LOA_1)).isTrue();
    }

    @Test
    void acrValuesIsASpaceSeparatedListOfAcceptableValues() {
        Authentication weak = authenticationWith(FactorGrantedAuthority.PASSWORD_AUTHORITY);

        // Any acceptable value being met is enough, whichever order they are listed in.
        assertThat(AuthenticationContextLevel.satisfies(weak,
                AuthenticationContextLevel.LOA_2 + " " + AuthenticationContextLevel.LOA_1)).isTrue();
        assertThat(AuthenticationContextLevel.satisfies(weak, "urn:demo:loa:9")).isFalse();
    }

    @Test
    void askingForNothingInParticularIsAlwaysSatisfied() {
        Authentication weak = authenticationWith(FactorGrantedAuthority.PASSWORD_AUTHORITY);

        assertThat(AuthenticationContextLevel.satisfies(weak, null)).isTrue();
        assertThat(AuthenticationContextLevel.satisfies(weak, "")).isTrue();
    }

    @Test
    void theStepUpPagesRequireASession() throws Exception {
        for (String path : List.of("/stepup", "/stepup/verify")) {
            mockMvc().perform(get(path)).andExpect(status().is3xxRedirection());
        }
    }
}
