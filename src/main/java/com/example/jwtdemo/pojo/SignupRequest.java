package com.example.jwtdemo.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;
@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignupRequest {
    private String username;
    private String password;
    private Set<String> roles;

}
