package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.security.FapiCheck;
import id.my.hendisantika.oauth2pkcedemo.service.FapiComplianceService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 17.32
 */
@Controller
@RequiredArgsConstructor
public class FapiController {

    private final FapiComplianceService fapiComplianceService;

    @GetMapping("/fapi")
    public String fapiPage(Model model) {
        List<FapiCheck> serverChecks = fapiComplianceService.serverChecks();
        Map<String, List<FapiCheck>> clientChecks = fapiComplianceService.clientChecks();

        model.addAttribute("serverChecks", serverChecks);
        model.addAttribute("clientChecks", clientChecks);
        model.addAttribute("serverFailures", countFailures(serverChecks));
        model.addAttribute("compliantClients", clientChecks.entrySet().stream()
                .filter(entry -> countFailures(entry.getValue()) == 0)
                .map(Map.Entry::getKey)
                .toList());
        return "fapi";
    }

    private static long countFailures(List<FapiCheck> checks) {
        return checks.stream().filter(check -> check.outcome() == FapiCheck.Outcome.FAIL).count();
    }
}
