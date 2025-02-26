package com.hinosecurity.hinosecurity.user.service;

import com.hinosecurity.hinosecurity.user.entity.User;
import com.hinosecurity.hinosecurity.user.model.JoinDTO;
import com.hinosecurity.hinosecurity.user.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {
    private UserRepository userRepository;

    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinDTO joinDTO) {
        User user = new User();

        user.setUsername(joinDTO.getUsername());
        user.setPassword(bCryptPasswordEncoder.encode(joinDTO.getPassword()));
        user.setRole("USER");
        userRepository.save(user);
    }

}
