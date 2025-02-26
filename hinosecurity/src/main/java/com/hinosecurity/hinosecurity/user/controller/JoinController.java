package com.hinosecurity.hinosecurity.user.controller;

import com.hinosecurity.hinosecurity.user.model.JoinDTO;
import com.hinosecurity.hinosecurity.user.service.JoinService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class JoinController {
    private JoinService joinService;

    @GetMapping("/join")
    public String joinP() {
        return "join";
    }

    @PostMapping
    public String joinProcess(JoinDTO joinDTO) {
        System.out.println(joinDTO.getUsername());
        System.out.println(joinDTO.getPassword());
        joinService.joinProcess(joinDTO);

        return "redirect:/login";
    }

}
