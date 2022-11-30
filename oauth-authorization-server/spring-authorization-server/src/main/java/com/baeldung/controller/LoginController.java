package com.baeldung.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

@Controller
public class LoginController {

    @GetMapping("/custom-login")
    public String redirectWithUsingRedirectView() {
        return "login";
    }

    @GetMapping("/custom-login-temp")
    public RedirectView redirectWithUsingRedirectView(RedirectAttributes attributes) {
        return new RedirectView("http://127.0.0.1:8081/login");
    }

}
