package com.cbretan.jwtapp.security;

import lombok.Data;

@Data
public class AuthResponse {
    private final boolean valid;
    private final String details;
}
