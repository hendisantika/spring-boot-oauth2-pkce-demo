package id.my.hendisantika.oauth2pkcedemo.controller;

import id.my.hendisantika.oauth2pkcedemo.security.DeviceAuthorization;
import id.my.hendisantika.oauth2pkcedemo.security.DevicePollResult;
import id.my.hendisantika.oauth2pkcedemo.service.DeviceFlowService;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 13.40
 */
@Controller
@RequiredArgsConstructor
public class DeviceFlowController {

    static final String DEVICE_AUTHORIZATION_ATTRIBUTE = "device.authorization";
    static final String DEVICE_RESULT_ATTRIBUTE = "device.result";

    private final DeviceFlowService deviceFlowService;

    /**
     * Stands in for the input-constrained device. Deliberately reachable without signing in: the
     * point of RFC 8628 is that this screen has no keyboard and no browser session of its own.
     */
    @GetMapping("/device")
    public String devicePage(HttpSession session, Model model) {
        model.addAttribute("authorization", session.getAttribute(DEVICE_AUTHORIZATION_ATTRIBUTE));
        model.addAttribute("result", session.getAttribute(DEVICE_RESULT_ATTRIBUTE));
        model.addAttribute("deviceScopes", deviceFlowService.deviceScopes());
        return "device";
    }

    @PostMapping("/device")
    public String requestDeviceCode(HttpSession session) {
        session.setAttribute(DEVICE_AUTHORIZATION_ATTRIBUTE, deviceFlowService.requestDeviceAuthorization());
        session.removeAttribute(DEVICE_RESULT_ATTRIBUTE);
        return "redirect:/device";
    }

    @PostMapping("/device/reset")
    public String reset(HttpSession session) {
        session.removeAttribute(DEVICE_AUTHORIZATION_ATTRIBUTE);
        session.removeAttribute(DEVICE_RESULT_ATTRIBUTE);
        return "redirect:/device";
    }

    /**
     * One poll of the token endpoint, shaped for the page's JavaScript so the browser can imitate a
     * device looping at the interval the server asked for.
     */
    @PostMapping("/device/poll")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> poll(HttpSession session) {
        if (!(session.getAttribute(DEVICE_AUTHORIZATION_ATTRIBUTE) instanceof DeviceAuthorization authorization)) {
            return ResponseEntity.badRequest().body(Map.of("status", "NONE"));
        }

        DevicePollResult result = deviceFlowService.poll(authorization);
        if (result.status() != DevicePollResult.Status.PENDING
                && result.status() != DevicePollResult.Status.SLOW_DOWN) {
            session.setAttribute(DEVICE_RESULT_ATTRIBUTE, result);
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", result.status().name());
        body.put("error", result.error());
        body.put("secondsRemaining", authorization.secondsRemaining());
        return ResponseEntity.ok(body);
    }

    /**
     * The page the {@code verification_uri} points at: where the human types the short code that was
     * displayed on the device.
     */
    @GetMapping("/activate")
    public String activate(@RequestParam(name = "user_code", required = false) String userCode,
                           @RequestParam(name = "error", required = false) String error,
                           Model model) {
        model.addAttribute("userCode", userCode);
        model.addAttribute("error", error);
        return "activate";
    }
}
