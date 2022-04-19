package com.example.jwtdemo;

import com.example.jwtdemo.domains.ERole;
import com.example.jwtdemo.domains.Role;
import com.example.jwtdemo.domains.Users;
import com.example.jwtdemo.repository.RoleRepository;
import com.example.jwtdemo.repository.UsersRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

import java.util.Set;

@SpringBootApplication
public class JwtDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtDemoApplication.class, args);
    }

}
