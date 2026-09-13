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

    private final OAuth2LoginRequiredInterceptor oAuth2LoginRequiredInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(oAuth2LoginRequiredInterceptor)
                .addPathPatterns("/dashboard", "/tokens", "/refresh", "/logout-demo", "/logout/rp-initiated");
    }
}
