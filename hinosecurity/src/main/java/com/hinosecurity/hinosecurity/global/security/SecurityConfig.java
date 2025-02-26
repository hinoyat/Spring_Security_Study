package com.hinosecurity.hinosecurity.global.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        // 모든 보안 기능 비활성화하되 URL 패턴은 유지
//        http
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/main", "/login", "/css/**", "/js/**", "/images/**").permitAll()
//                        .anyRequest().permitAll()  // 테스트를 위해 모든 요청 허용
//                )
//                .formLogin(form -> form.disable())  // 폼 로그인 비활성화
//                .httpBasic(basic -> basic.disable())  // HTTP 기본 인증 비활성화
//                .csrf(csrf -> csrf.disable());       // CSRF 보호 비활성화
//
//        return http.build();
//    }
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

    http
            .authorizeHttpRequests((auth) -> auth
                    .requestMatchers("/", "/login", "/loginProc").permitAll()
                    .requestMatchers("/admin").hasRole("ADMIN")
                    .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                    .anyRequest().authenticated()
            );


    http
            .formLogin((auth) -> auth.loginPage("/login")
                    .loginProcessingUrl("/loginProc")
                    .permitAll()
            );

    http
            .csrf((auth) -> auth.disable());


    return http.build();
    }

}