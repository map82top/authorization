package com.example.authorization.controller;

import com.example.authorization.message.request.LoginForm;
import com.example.authorization.message.request.SignUpForm;
import com.example.authorization.message.response.JwtResponse;
import com.example.authorization.model.User;
import com.example.authorization.repository.UserRepository;
import com.example.authorization.security.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/")
public class HomeRestAPIs {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtProvider jwtProvider;

    @GetMapping("/home")
    public ResponseEntity<?> getHome(@RequestHeader("Authorization") String autorization) {
        String token = getJwt(autorization);
        String username = jwtProvider.getUserNameFromAccessJwtToken(token);

        return ResponseEntity.ok().body(String.format(" %s, hello world!", username));
    }

    private String getJwt(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            return token.replace("Bearer ","");
        }

        return null;
    }
}
