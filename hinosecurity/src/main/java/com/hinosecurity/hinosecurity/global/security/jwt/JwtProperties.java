package com.hinosecurity.hinosecurity.global.security.jwt;


import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    private String secretKey = "yourVerySecretKeyHereItShouldBeAtLeast32CharactersLong";
    private long accessTokenValidityInMs = 3600000; // 1시간
    private long refreshTokenValidityInMs = 2592000000L; // 30일
    private String tokenPrefix = "Bearer ";
    private String headerString = "Authorization";
}
