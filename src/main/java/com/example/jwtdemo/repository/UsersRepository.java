package com.example.jwtdemo.repository;

import com.example.jwtdemo.domains.ERole;
import com.example.jwtdemo.domains.Role;
import com.example.jwtdemo.domains.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsersRepository extends JpaRepository<Users, Long> {
    Optional<Users> findByUsername(String username);
    boolean existsByUsername(String username);
}
