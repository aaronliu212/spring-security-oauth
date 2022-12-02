package com.baeldung.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/custom-login-temp")
    public String redirectWithUsingRedirectView() {
        return "login";
    }

/*    @GetMapping("/custom-login")
    public RedirectView redirectWithUsingRedirectView(RedirectAttributes attributes) {
        return new RedirectView("http://127.0.0.1:8081/login");
    }*/

}
