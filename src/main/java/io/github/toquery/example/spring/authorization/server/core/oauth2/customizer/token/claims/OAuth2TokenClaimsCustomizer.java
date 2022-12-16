package io.github.toquery.example.spring.authorization.server.core.oauth2.customizer.token.claims;

import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;

public interface OAuth2TokenClaimsCustomizer {

	void customizeTokenClaims(OAuth2TokenClaimsContext context);

}
