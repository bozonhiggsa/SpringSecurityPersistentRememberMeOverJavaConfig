package com.application.springSecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Controller for requests handling
 * @author Ihor Savchenko
 * @version 1.0
 */
@Controller
public class MvcController {

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String index() {
        return "index";
    }

    @GetMapping(value= "/auth")
    public String authVarious() {
        return "variousUsers";
    }

    @GetMapping(value= "/admin/auth")
    public String authOnlyAdmin() {
        return "onlyAdmin";
    }

    @GetMapping(value= "/forbid")
    public String authNobody() {
        return "forEverybody";
    }

    @GetMapping(value= "/permit")
    public String authEverybody() {
        return "forEverybody";
    }

    @GetMapping(value= "/anonymous")
    public String authAnonymous() {
        return "forAnonymous";
    }

    @GetMapping(value= "/authenticated")
    public String authAuthenticated() {
        return "forAuthenticated";
    }

    @GetMapping(value= "/fullyAuthenticated")
    public String authFullyAuthenticated() {
        return "forFullyAuthenticated";
    }

    @GetMapping(value= "/rememberMe")
    public String authRememberMe() {
        return "forRememberMe";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping(value= "/method")
    public String exampleForMethodPreAuthorize() {
        return "forMethodPreAuthorize";
    }

    @GetMapping(value= "/login")
    public String toLogin() {
        return "login2";
    }


}
