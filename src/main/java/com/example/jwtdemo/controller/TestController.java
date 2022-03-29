package com.example.jwtdemo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {
    @GetMapping("/all")
    public String getAll(){
        return "public API";
    }
    @GetMapping("/user")
    public String getApiUser(){
        return "USER API";
    }
    @GetMapping("/mod")
    public String getApiMod(){
        return "CREATOR API";
    }
    @GetMapping("/admin")
    public String getApiAdmin(){
        return "BOSS API";
    }
}
