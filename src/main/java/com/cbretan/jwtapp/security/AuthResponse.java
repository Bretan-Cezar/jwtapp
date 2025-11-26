package com.cbretan.jwtapp.security;

public record AuthResponse(boolean valid, String details) {
}
