package io.github.toquery.example.spring.authorization.server.core.oauth2.federated.identity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.util.ForwardedHeaderUtils;

import java.io.IOException;

public final class FederatedIdentityAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Setter
    private String authorizationRequestUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/{registrationId}";

    private final AuthenticationEntryPoint delegate;

    private final ClientRegistrationRepository clientRegistrationRepository;

    public FederatedIdentityAuthenticationEntryPoint(String loginPageUrl, ClientRegistrationRepository clientRegistrationRepository) {
        this.delegate = new LoginUrlAuthenticationEntryPoint(loginPageUrl);
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException) throws IOException, ServletException {
        String idp = request.getParameter("idp");
        if (idp != null) {
            ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(idp);
            if (clientRegistration != null) {
                ServletServerHttpRequest servletServerHttpRequest = new ServletServerHttpRequest(request);
                String redirectUri = ForwardedHeaderUtils.adaptFromForwardedHeaders(servletServerHttpRequest.getURI(), servletServerHttpRequest.getHeaders())
                        .replaceQuery(null).replacePath(this.authorizationRequestUri)
                        .buildAndExpand(clientRegistration.getRegistrationId()).toUriString();
                this.redirectStrategy.sendRedirect(request, response, redirectUri);
                return;
            }
        }

        this.delegate.commence(request, response, authenticationException);
    }

}
