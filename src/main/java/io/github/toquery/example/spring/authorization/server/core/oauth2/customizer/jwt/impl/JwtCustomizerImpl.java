package io.github.toquery.example.spring.authorization.server.core.oauth2.customizer.jwt.impl;

import io.github.toquery.example.spring.authorization.server.core.oauth2.customizer.jwt.JwtCustomizer;
import io.github.toquery.example.spring.authorization.server.core.oauth2.customizer.jwt.JwtCustomizerHandler;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

public class JwtCustomizerImpl implements JwtCustomizer {

	private final JwtCustomizerHandler jwtCustomizerHandler;

	public JwtCustomizerImpl(JwtCustomizerHandler jwtCustomizerHandler) {
		this.jwtCustomizerHandler = jwtCustomizerHandler;
	}

	@Override
	public void customizeToken(JwtEncodingContext jwtEncodingContext) {
		jwtCustomizerHandler.customize(jwtEncodingContext);
	}

}
