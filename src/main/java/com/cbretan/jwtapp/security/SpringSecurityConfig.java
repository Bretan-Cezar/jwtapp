package com.cbretan.jwtapp.security;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SpringSecurityConfig {

    private final AuthorizationFilter authorizationFilter;

    /**
     * Spring Security filter chain configuration.
     * CORS - placeholder settings, "*" not to be used in production.
     * Session - sessions never used or created for REST APIs
     * CSRF - disabled, CSRF tokens replaced by JWT tokens
     * Authorization Filters:
     *  - Default Spring filter - set to bypass for all matchers
     *  - Custom Filter - placed right before the default filter
     * Exception Handling - yields 500 status code as a fallback for any unknown error
     * @param http HTTP Security configuration object
     * @return built configuration object
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) {

        http
                .cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource()))
                .sessionManagement(customizer -> customizer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((customizer -> customizer.requestMatchers("/**").permitAll()))
                .exceptionHandling(customizer -> customizer.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.INTERNAL_SERVER_ERROR)))
                .addFilterBefore(authorizationFilter, org.springframework.security.web.access.intercept.AuthorizationFilter.class);

        return http.build();
    }

    private CorsConfigurationSource corsConfigurationSource() {
        var corsConfig = new CorsConfiguration();

        // TODO tweak allowed parameters
        corsConfig.setAllowedHeaders(List.of("*"));
        corsConfig.setAllowedOrigins(List.of("*"));
        corsConfig.setAllowedMethods(List.of("*"));

        var urlCorsConfig = new UrlBasedCorsConfigurationSource();
        urlCorsConfig.registerCorsConfiguration("/**", corsConfig);

        return urlCorsConfig;
    }
}
