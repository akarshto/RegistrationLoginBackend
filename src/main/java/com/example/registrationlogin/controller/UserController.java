package com.example.registrationlogin.controller;

import com.example.registrationlogin.dto.MessageResponse;
import com.example.registrationlogin.dto.SignupRequest;
import com.example.registrationlogin.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/registration")
    public ResponseEntity<MessageResponse> register(@Valid @RequestBody SignupRequest request) {
        userService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new MessageResponse("Registration successful"));
    }
}
