package com.example.jwtdemo.service;

import com.example.jwtdemo.config.jwt.JwtUtils;
import com.example.jwtdemo.domains.ERole;
import com.example.jwtdemo.domains.Role;
import com.example.jwtdemo.domains.Users;
import com.example.jwtdemo.pojo.JwtResponse;
import com.example.jwtdemo.pojo.LoginRequest;
import com.example.jwtdemo.pojo.SignupRequest;
import com.example.jwtdemo.repository.RoleRepository;
import com.example.jwtdemo.repository.UsersRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UsersService {
    private final UsersRepository usersRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;


    public UsersService(UsersRepository usersRepository, RoleRepository roleRepository, PasswordEncoder encoder, AuthenticationManager authenticationManager, JwtUtils jwtUtils) {
        this.usersRepository = usersRepository;
        this.roleRepository = roleRepository;
        this.encoder = encoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }

    public Users save(SignupRequest signupRequest){
        if (usersRepository.existsByEmail(signupRequest.getEmail()) || usersRepository.existsByUsername(signupRequest.getUsername())) {
           throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        Users users = new Users(signupRequest.getUsername(), signupRequest.getEmail(), encoder.encode(signupRequest.getPassword()));
        Set<String> reqRoles = signupRequest.getRoles();
        Set<Role> roles = new HashSet<>();
        if (reqRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER).get();
            roles.add(userRole);
        } else {
            reqRoles.forEach(r -> {
                switch (r) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_BOSS).get();
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_CREATOR).get();
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER).get();
                        roles.add(userRole);
                        break;
                }
            });
        }
        users.setRoles(roles);
        return usersRepository.save(users);
    }
    public JwtResponse signin(LoginRequest loginRequest){
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        UsersDetailsImpl usersDetails = (UsersDetailsImpl) authentication.getPrincipal();
        List<String> roles = usersDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        return new JwtResponse(jwt, usersDetails.getId(), usersDetails.getUsername(), usersDetails.getEmail(), roles);
    }
}
