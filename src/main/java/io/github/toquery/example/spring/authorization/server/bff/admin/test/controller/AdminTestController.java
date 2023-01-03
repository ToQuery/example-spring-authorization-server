package io.github.toquery.example.spring.authorization.server.bff.admin.test.controller;

import io.github.toquery.example.spring.authorization.server.core.utils.AuthenticationUtils;
import lombok.SneakyThrows;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 *
 */
@RestController
@RequestMapping("/admin/test")
public class AdminTestController {

    @SneakyThrows
    @ResponseBody
    @GetMapping(value = {"", "/", "/index", "/info"})
    public Map<String, Object> info(
            Authentication authentication,
            @AuthenticationPrincipal OAuth2User oauth2User
    ) {
        return AuthenticationUtils.authenticationInfo(this.getClass().getSimpleName(), authentication, oauth2User, null);
    }
}
