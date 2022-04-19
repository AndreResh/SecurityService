package com.example.jwtdemo.service;

import com.example.jwtdemo.config.jwt.JwtUtils;
import com.example.jwtdemo.domains.ERole;
import com.example.jwtdemo.domains.Role;
import com.example.jwtdemo.domains.Users;
import com.example.jwtdemo.pojo.*;
import com.example.jwtdemo.repository.RoleRepository;
import com.example.jwtdemo.repository.UsersRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jdk.jshell.execution.Util;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UsersService {
    private final UsersRepository usersRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    @Value("${user.service.url}")
    private String userURL;
    private final RestTemplate restTemplate;
    @Value("${user.app.secret}")
    private String jwtForUserService;
    @Value("${user.app.time}")
    private int jwtTimeForUserService;

    public Users register(SignupRequest signupRequest) {
        if (usersRepository.existsByUsername(signupRequest.getUsername())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User in DB");
        }
        Users users = new Users(signupRequest.getUsername(), encoder.encode(signupRequest.getPassword()));
        users.setRoles(Set.of(roleRepository.findByName(ERole.ROLE_USER).get()));
        users.setId(createUser(signupRequest.getUsername()));
        return usersRepository.save(users);
    }

    public JwtResponse login(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        UsersDetailsImpl usersDetails = (UsersDetailsImpl) authentication.getPrincipal();
        List<String> roles = usersDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        return new JwtResponse(jwt, usersDetails.getId(), usersDetails.getUsername(), roles);
    }

    private Long createUser(String username) {
        try {
            ResponseEntity<UserResponse> responseEntity = restTemplate.postForEntity(userURL,
                    new HttpEntity<>(Map.of("name", username), createHeader(username)), UserResponse.class);
            if (Objects.requireNonNull(responseEntity.getBody()).getUserId() == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Can't create user");
            }
            return responseEntity.getBody().getUserId();
        } catch (HttpClientErrorException e){
            throw new ResponseStatusException(e.getStatusCode());
        }
    }

    private HttpHeaders createHeader(String username) {
        String jwt = Jwts.builder().setSubject(username).setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtTimeForUserService))
                .signWith(SignatureAlgorithm.HS512, jwtForUserService).compact();
        return new HttpHeaders() {{
            set("Authorization", "Bearer " + jwt);
        }};
    }

    public Users changePassword(Long id, ChangePassword changePassword, UserDetails details) {
        Optional<Users> optionalUsers1= usersRepository.findById(id);
        Optional<Users> optionalUsers2;
        try {
             optionalUsers2 = usersRepository.findByUsername(details.getUsername());
        } catch (Exception e){
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        if(!optionalUsers1.isPresent()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User with this id not fount");
        }
        Users users=optionalUsers1.get();
        if(!optionalUsers2.get().getId().equals(users.getId())){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        if (!encoder.matches(changePassword.getOldPassword(), users.getPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Current password doesn't equals your old password");
        }
        users.setPassword(encoder.encode(changePassword.getNewPassword()));
        return usersRepository.save(users);
    }
}
