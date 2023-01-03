package io.github.toquery.example.spring.authorization.server.core.utils;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class AuthenticationUtils {
    private AuthenticationUtils() {
    }

    public static Map<String, Object> authenticationInfo(String name,Authentication authentication, OAuth2User oauth2User, OAuth2AuthorizedClient authorizedClient) {
        Map<String, Object> map = new HashMap<>();
        map.put("name", name);

        map.put("authentication", authentication);
        if (authentication != null) {
            map.put("authentication.getClass().getName()", authentication.getClass().getName());
        }
        map.put("authorizedClient", authorizedClient);
        map.put("oauth2User", oauth2User);
        return map;
    }
}
