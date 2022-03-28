package com.example.jwtdemo;

import com.example.jwtdemo.domains.ERole;
import com.example.jwtdemo.domains.Role;
import com.example.jwtdemo.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class JwtDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtDemoApplication.class, args);
    }

//    @Bean
//    public CommandLineRunner runner(RoleRepository repository) {
//        return args -> {
//          repository.save(new Role(ERole.ROLE_USER));
//            repository.save(new Role(ERole.ROLE_MODERATOR));
//            repository.save(new Role(ERole.ROLE_ADMIN));
//        };
//    }
}
