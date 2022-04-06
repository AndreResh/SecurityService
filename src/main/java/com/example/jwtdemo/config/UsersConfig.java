package com.example.jwtdemo.config;

import com.example.jwtdemo.domains.ERole;
import com.example.jwtdemo.domains.Role;
import com.example.jwtdemo.domains.Users;
import com.example.jwtdemo.repository.RoleRepository;
import com.example.jwtdemo.repository.UsersRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.web.client.RestTemplate;


import java.util.*;


@Configuration
public class UsersConfig {
    @Bean
    public CommandLineRunner runner(RoleRepository repository, UsersRepository usersRepository) {
        return args -> {
            if (!repository.findByName(ERole.ROLE_USER).isPresent()) {
                repository.save(new Role(ERole.ROLE_USER));
            }
            if (!repository.findByName(ERole.ROLE_CREATOR).isPresent()) {
                repository.save(new Role(ERole.ROLE_CREATOR));
            }
            if (!repository.findByName(ERole.ROLE_BOSS).isPresent()) {
                repository.save(new Role(ERole.ROLE_BOSS));
            }
            if(!usersRepository.existsByUsername("boss")){
                usersRepository.save(new Users(1L, "boss", "$2a$10$5sVDbWqWHWd3OVUCG1kcyOm3eN/Q4FwiQ0ZYh51p9owo3DMEeqhna",
                        Set.of(repository.findByName(ERole.ROLE_BOSS).get())));
            }
            if(!usersRepository.existsByUsername("creator")){
                usersRepository.save(new Users(2L, "creator", "$2a$10$Mg26fxH2wg84bEQzplS2W.8rgi86FrKmrFFQMokhH8xR/6TO2BgwW",
                        Set.of(repository.findByName(ERole.ROLE_CREATOR).get())));
            }
        };
    }
    @Bean
    public RestTemplate restTemplate(){
        return new RestTemplate();
    }
}
