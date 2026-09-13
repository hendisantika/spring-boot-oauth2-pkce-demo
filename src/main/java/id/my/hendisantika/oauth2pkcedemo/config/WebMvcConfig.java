package id.my.hendisantika.oauth2pkcedemo.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.21
 */
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class WebMvcConfig implements WebMvcConfigurer {

    /** Pages that read tokens out of the authorized client store. */
    private static final String[] TOKEN_PAGES =
            {"/dashboard", "/tokens", "/refresh", "/introspect", "/introspect/**", "/dpop", "/exchange"};

    private final OAuth2LoginRequiredInterceptor oAuth2LoginRequiredInterceptor;
    private final AuthorizedClientRequiredInterceptor authorizedClientRequiredInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(oAuth2LoginRequiredInterceptor)
                .addPathPatterns(TOKEN_PAGES)
                .addPathPatterns("/logout-demo", "/logout/rp-initiated");
        // The logout pages only need the ID token off the principal, so they are left out here: a
        // session with no stored tokens can still sign itself out.
        registry.addInterceptor(authorizedClientRequiredInterceptor)
                .addPathPatterns(TOKEN_PAGES);
    }
}
