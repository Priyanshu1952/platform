package com.tj.services.ums.controller;

import com.tj.services.ums.service.EmailVerificationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EmailVerificationController {

    @Autowired
    private EmailVerificationService emailVerificationService;

    @GetMapping("/verify-email")
    public String verifyEmail(@RequestParam("token") String token) {
        emailVerificationService.verifyEmail(token);
        return "Email verified successfully!";
    }
}