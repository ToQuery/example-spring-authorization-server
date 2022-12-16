package io.github.toquery.example.spring.authorization.server.core.oauth2.customizer.jwt.impl;

import io.github.toquery.example.spring.authorization.server.core.oauth2.customizer.jwt.JwtCustomizerHandler;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

public class DefaultJwtCustomizerHandler implements JwtCustomizerHandler {

	@Override
	public void customize(JwtEncodingContext jwtEncodingContext) {
		// does not modify any thing in context

	}

}
