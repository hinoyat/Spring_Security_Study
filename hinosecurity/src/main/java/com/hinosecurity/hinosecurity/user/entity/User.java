package com.hinosecurity.hinosecurity.user.entity;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Column(unique = true) // 중복 방지를 위한 설정
    private String username;

    private String password;

    private String role;
}
