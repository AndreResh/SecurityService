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
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
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
        ResponseEntity<UserResponse> responseEntity = restTemplate.postForEntity(userURL,
                new HttpEntity<>(Map.of("name", username), createHeader(username)), UserResponse.class);
        if (Objects.requireNonNull(responseEntity.getBody()).getUserId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        return responseEntity.getBody().getUserId();
    }

    private HttpHeaders createHeader(String username) {
        String jwt = Jwts.builder().setSubject(username).setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtTimeForUserService))
                .signWith(SignatureAlgorithm.HS512, jwtForUserService).compact();
        return new HttpHeaders() {{
            set("Authorization", "Bearer " + jwt);
        }};
    }

    public Users changePassword(Long id, ChangePassword changePassword) {
        Optional<Users> optionalUsers= usersRepository.findById(id);
        if(!optionalUsers.isPresent()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        Users users=optionalUsers.get();
        if (!encoder.matches(changePassword.getOldPassword(), users.getPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        users.setPassword(encoder.encode(changePassword.getNewPassword()));
        return usersRepository.save(users);
    }
}
