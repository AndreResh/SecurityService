package com.example.jwtdemo.controller;

import com.example.jwtdemo.config.jwt.JwtUtils;
import com.example.jwtdemo.domains.ERole;
import com.example.jwtdemo.domains.Role;
import com.example.jwtdemo.domains.Users;
import com.example.jwtdemo.pojo.JwtResponse;
import com.example.jwtdemo.pojo.LoginRequest;
import com.example.jwtdemo.pojo.MessageResponse;
import com.example.jwtdemo.pojo.SignupRequest;
import com.example.jwtdemo.repository.RoleRepository;
import com.example.jwtdemo.repository.UsersRepository;
import com.example.jwtdemo.service.UsersDetailsImpl;
import com.example.jwtdemo.service.UsersService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UsersService usersService;

    public AuthController(UsersService usersService) {
        this.usersService = usersService;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authUser(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(usersService.signin(loginRequest));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest) {
        return ResponseEntity.ok(usersService.save(signupRequest));
    }
}
