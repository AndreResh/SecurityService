package com.example.jwtdemo.config.jwt;

import com.example.jwtdemo.service.UsersDetailsImpl;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {
    @Value("${my.app.secret}")
    private String jwtSecret;
    @Value("${my.app.expiration}")
    private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {
        UsersDetailsImpl usersDetails = (UsersDetailsImpl) authentication.getPrincipal();
        System.out.println(usersDetails.getUsername());
        return Jwts.builder().setSubject((usersDetails.getId()+" "+usersDetails.getUsername()+" "+usersDetails.getAuthorities())).setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret).compact();
    }

    public boolean validateJwtToken(String jwt) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(jwt);
            return true;
        } catch (MalformedJwtException | IllegalArgumentException e) {
            System.err.println(e.getLocalizedMessage());
        }
        return false;
    }

    public String getUserNameFromJwtToken(String jwt) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(jwt).getBody().getSubject();
    }
}
