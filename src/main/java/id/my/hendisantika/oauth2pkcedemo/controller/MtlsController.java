package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.config.DemoProperties;
import id.my.hendisantika.oauth2pkcedemo.security.MtlsMaterial;
import id.my.hendisantika.oauth2pkcedemo.service.MtlsService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 15.02
 */
@Controller
@RequiredArgsConstructor
public class MtlsController {

    private final MtlsService mtlsService;
    private final MtlsMaterial mtlsMaterial;
    private final DemoProperties properties;

    @GetMapping("/mtls")
    public String mtlsPage(Model model) {
        model.addAttribute("clientId", properties.mtlsClient().clientId());
        model.addAttribute("scopes", String.join(" ", properties.mtlsClient().scopes()));
        model.addAttribute("tokenEndpoint", mtlsService.tokenEndpoint());
        model.addAttribute("subjectDn", mtlsMaterial.clientSubjectDn());
        model.addAttribute("thumbprint", mtlsMaterial.clientCertificateThumbprint());
        model.addAttribute("jwkSetUri", MtlsJwkSetController.MTLS_JWK_SET_URI);
        return "mtls";
    }

    @PostMapping("/mtls")
    public String run(RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("attempts", mtlsService.run());
        return "redirect:/mtls";
    }
}
