package com.example.jwtdemo.controller;

import com.example.jwtdemo.pojo.ChangePassword;
import com.example.jwtdemo.pojo.LoginRequest;
import com.example.jwtdemo.pojo.SignupRequest;
import com.example.jwtdemo.service.UsersService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@Slf4j
@RestController
@RequestMapping("/authenticate")
public class AuthController {

    private final UsersService usersService;

    public AuthController(UsersService usersService) {
        this.usersService = usersService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest loginRequest) {
        log.info("Login user: {}", loginRequest);
        return ResponseEntity.ok(usersService.login(loginRequest));
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        log.info("Register user: {}", signupRequest);
        return ResponseEntity.ok(usersService.register(signupRequest));
    }

    @PatchMapping("/{id}/changePassword")
    public ResponseEntity<?> changePassword(@PathVariable("id") Long id, @AuthenticationPrincipal UserDetails details, @RequestBody ChangePassword changePassword) {
        log.info("Change password: {}", changePassword);
        return ResponseEntity.ok(usersService.changePassword(id, changePassword, details));
    }
}
