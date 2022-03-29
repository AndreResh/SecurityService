package com.example.jwtdemo.controller;

import com.example.jwtdemo.pojo.LoginRequest;
import com.example.jwtdemo.pojo.SignupRequest;
import com.example.jwtdemo.service.UsersService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/authenticate")
public class AuthController {

    private final UsersService usersService;

    public AuthController(UsersService usersService) {
        this.usersService = usersService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginRequest loginRequest) {
        log.info("Login user: {}",loginRequest);
        return ResponseEntity.ok(usersService.login(loginRequest));
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest) {
        log.info("Register user: {}",signupRequest);
        return ResponseEntity.ok(usersService.register(signupRequest));
    }
}
