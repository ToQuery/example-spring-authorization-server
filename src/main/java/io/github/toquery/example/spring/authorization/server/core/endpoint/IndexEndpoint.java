package io.github.toquery.example.spring.authorization.server.core.endpoint;

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
public class IndexEndpoint {

    @RequestMapping(value = {"/", "/index"})
    public Map<String,Object> index(){
        Map<String,Object> map = new HashMap<>();
        map.put("name", "index");
        return map;
    }

}
