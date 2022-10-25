package io.github.toquery.example.spring.authorization.server.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */
@RestController
@RequestMapping
public class IndexController {

    @RequestMapping(value = {"/", "/index"})
    public Map<String,Object> index(){
        Map<String,Object> map = new HashMap<>();
        map.put("name", "index");
        return map;
    }

    @RequestMapping(value = "/info")
    public Map<String,Object> info(Authentication authentication){
        Map<String,Object> map = new HashMap<>();
        map.put("name", "info");
        map.put("authenticationClass", authentication.getClass().getName());
        map.put("authentication", authentication);
        return map;
    }
}
