package org.springframework.security.oauth2.server.authorization.web;

import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.Writer;

/**
 * A {@code Filter} that processes JWK Set requests.
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see JWKSource
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517">JSON Web Key (JWK)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7517#section-5">Section 5 JWK Set Format</a>
*/
//public final class NimbusJwkSetEndpointFilter extends OncePerRequestFilter {
//	/**
//	 * The default endpoint {@code URI} for JWK Set requests.
//	 */
//	private static final String DEFAULT_JWK_SET_ENDPOINT_URI = "/oauth2/jwks";
//
//	private final JWKSource<SecurityContext> jwkSource;
//	private final JWKSelector jwkSelector;
//	private final RequestMatcher requestMatcher;
//
//	/**
//	 * Constructs a {@code NimbusJwkSetEndpointFilter} using the provided parameters.
//	 * @param jwkSource the {@code com.nimbusds.jose.jwk.source.JWKSource}
//	 */
//	public NimbusJwkSetEndpointFilter(JWKSource<SecurityContext> jwkSource) {
//		this(jwkSource, DEFAULT_JWK_SET_ENDPOINT_URI);
//	}
//
//	/**
//	 * Constructs a {@code NimbusJwkSetEndpointFilter} using the provided parameters.
//	 *
//	 * @param jwkSource the {@code com.nimbusds.jose.jwk.source.JWKSource}
//	 * @param jwkSetEndpointUri the endpoint {@code URI} for JWK Set requests
//	 */
//	public NimbusJwkSetEndpointFilter(JWKSource<SecurityContext> jwkSource, String jwkSetEndpointUri) {
//		Assert.notNull(jwkSource, "jwkSource cannot be null");
//		Assert.hasText(jwkSetEndpointUri, "jwkSetEndpointUri cannot be empty");
//		this.jwkSource = jwkSource;
//		this.jwkSelector = new JWKSelector(new JWKMatcher.Builder().build());
//		this.requestMatcher = new AntPathRequestMatcher(jwkSetEndpointUri, HttpMethod.GET.name());
//	}
//
//	@Override
//	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//			throws ServletException, IOException {
//
//		if (!this.requestMatcher.matches(request)) {
//			filterChain.doFilter(request, response);
//			return;
//		}
//
//		JWKSet jwkSet;
//		try {
//			jwkSet = new JWKSet(this.jwkSource.get(this.jwkSelector, null));
//		}
//		catch (Exception ex) {
//			throw new IllegalStateException("Failed to select the JWK(s) -> " + ex.getMessage(), ex);
//		}
//
//		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//		try (Writer writer = response.getWriter()) {
//			writer.write(jwkSet.toString());	// toString() excludes private keys
//		}
//	}
//}
