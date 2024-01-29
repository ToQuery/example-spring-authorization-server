package io.github.toquery.example.spring.authorization.server;

import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

/**
 *
 */
@Slf4j
@SpringBootTest
@AutoConfigureMockMvc
public class AuthorizationTest {

    @Resource
    private MockMvc mockMvc;

    @Test
    public void clientCredentials() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .post("/oauth2/token")
                                .param("grant_type", AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                                .param("scope", OidcScopes.PROFILE)
                                .with(SecurityMockMvcRequestPostProcessors.httpBasic("example", "example-secret"))
                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.access_token").exists())
                .andExpect(MockMvcResultMatchers.jsonPath("$.token_type").exists())
                .andExpect(MockMvcResultMatchers.jsonPath("$.expires_in").exists())
                .andExpect(MockMvcResultMatchers.jsonPath("$.scope").exists())
                .andExpect(MockMvcResultMatchers.jsonPath("$.access_token").isNotEmpty());
    }

    @Test
    public void password() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .post("/oauth2/token")
                                .param("grant_type", AuthorizationGrantType.PASSWORD.getValue())

                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string("root"));
    }
}
