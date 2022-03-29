package com.example.jwtdemo.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
@Slf4j
@RestController
@RequestMapping("/api/test")
public class TestController {
    @GetMapping("/all")
    public String getAll(){
        log.info("GET ALL");
        return "public API";
    }
    @GetMapping("/user")
    public String getApiUser(){
        log.info("GET USER");
        return "USER API";
    }
    @GetMapping("/mod")
    public String getApiMod(){
        log.info("GET MOD");
        return "CREATOR API";
    }
    @GetMapping("/admin")
    public String getApiAdmin(){
        log.info("GET BOSS");
        return "BOSS API";
    }
}
