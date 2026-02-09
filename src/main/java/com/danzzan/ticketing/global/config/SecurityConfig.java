package com.danzzan.ticketing.global.config;

import com.danzzan.ticketing.global.security.AdminAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfigurationSource corsConfigurationSource;
    private final AdminAuthenticationFilter adminAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Swagger UI
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                        // 회원가입, 로그인은 인증 없이 접근 가능
                        .requestMatchers("/user/login").permitAll()
                        .requestMatchers("/user/dku/**").permitAll()
                        .requestMatchers("/user/{signup-token}").permitAll()
                        // 관리자 로그인은 인증 없이 접근 가능 (more specific path first)
                        .requestMatchers("/api/admin/auth/login").permitAll()
                        // 관리자 API는 인증 필요
                        .requestMatchers("/api/admin/**").authenticated()
                        // 나머지는 인증 필요 (일단 전체 허용으로 설정)
                        .anyRequest().permitAll()
                )
                .addFilterBefore(adminAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
