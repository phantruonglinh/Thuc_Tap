package com.example.SpringBootSecurity.security.services;

import com.example.SpringBootSecurity.models.User;
import com.example.SpringBootSecurity.payload.request.LoginRequest;
import com.example.SpringBootSecurity.payload.request.SignupRequest;
import com.example.SpringBootSecurity.payload.response.JwtResponse;
import com.example.SpringBootSecurity.payload.response.MessageResponse;

public interface UserService {
    JwtResponse login(LoginRequest loginRequest);
    MessageResponse registerUser(SignupRequest signupRequest);
    Boolean delUser(Long id);
    MessageResponse updateUser(String user,SignupRequest signupRequest);
}
