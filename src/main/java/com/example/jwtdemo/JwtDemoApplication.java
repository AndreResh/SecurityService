package com.example.jwtdemo;

import com.example.jwtdemo.domains.ERole;
import com.example.jwtdemo.domains.Role;
import com.example.jwtdemo.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
public class JwtDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtDemoApplication.class, args);
    }

    @Bean
    public CommandLineRunner runner(RoleRepository repository) {
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
        };
    }
    @Bean
    public RestTemplate restTemplate(){
        return new RestTemplate();
    }
}
