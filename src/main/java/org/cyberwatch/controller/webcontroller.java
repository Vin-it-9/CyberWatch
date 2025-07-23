package org.cyberwatch.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class webcontroller {

    @GetMapping("/")
    public String index() {
        return "redirect:/dashboard";
    }

}
