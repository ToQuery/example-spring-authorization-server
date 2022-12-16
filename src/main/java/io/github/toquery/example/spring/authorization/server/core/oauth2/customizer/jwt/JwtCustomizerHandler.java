package io.github.toquery.example.spring.authorization.server.core.oauth2.customizer.jwt;

import io.github.toquery.example.spring.authorization.server.core.oauth2.customizer.jwt.impl.DefaultJwtCustomizerHandler;
import io.github.toquery.example.spring.authorization.server.core.oauth2.customizer.jwt.impl.OAuth2AuthenticationTokenJwtCustomizerHandler;
import io.github.toquery.example.spring.authorization.server.core.oauth2.customizer.jwt.impl.UsernamePasswordAuthenticationTokenJwtCustomizerHandler;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

public interface JwtCustomizerHandler {

	void customize(JwtEncodingContext jwtEncodingContext);

	static JwtCustomizerHandler getJwtCustomizerHandler() {

		JwtCustomizerHandler defaultJwtCustomizerHandler = new DefaultJwtCustomizerHandler();
//		JwtCustomizerHandler oauth2AuthenticationTokenJwtCustomizerHandler = new OAuth2AuthenticationTokenJwtCustomizerHandler(defaultJwtCustomizerHandler);
//		JwtCustomizerHandler usernamePasswordAuthenticationTokenJwtCustomizerHandler = new UsernamePasswordAuthenticationTokenJwtCustomizerHandler(oauth2AuthenticationTokenJwtCustomizerHandler);
//		return usernamePasswordAuthenticationTokenJwtCustomizerHandler;

		return null;

	}

}
