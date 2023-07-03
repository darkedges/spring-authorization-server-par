package org.springframework.security.oauth2.server.authorization.web;

import java.io.IOException;
import org.springframework.security.core.AuthenticationException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import darkedges.OAuth2PushedAuthorizationRequest;
import darkedges.OAuth2PushedAuthorizationRequestAuthenticationToken;
import darkedges.OAuth2PushedAuthorizationRequestHttpMessageConverter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class OAuth2PushedAuthorizationRequestEndpointFilter extends OncePerRequestFilter {
	public static final String DEFAULT_PUSHED_AUTHORIZATION_REQUEST_ENDPOINT_URI = "/oauth2/par";
	private final RequestMatcher pushedAuthorizationRequestEndpointMatcher;
	private final AuthenticationManager authenticationManager;
	private final Log logger = LogFactory.getLog(getClass());
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
	private final HttpMessageConverter<OAuth2PushedAuthorizationRequest> pushedAuthorizationRequestHttpResponseConverter =
			new OAuth2PushedAuthorizationRequestHttpMessageConverter();
	private AuthenticationConverter authenticationConverter;
	private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendPushedAuthorizationRequestResponse;
	private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();
	private boolean requirePushedAuthorizationRequests;
	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestEndpointFilter} using
	 * the provided parameters.
	 *
	 * @param pushedAuthorizationRequestEndpointUri the endpoint {@code URI} for
	 *                                              pushed authorization request
	 *                                              requests
	 */
	public OAuth2PushedAuthorizationRequestEndpointFilter(AuthenticationManager authenticationManager,
			String pushedAuthorizationRequestEndpointUri) {
		Assert.hasText(pushedAuthorizationRequestEndpointUri, "pushedAuthorizationRequestEndpointUri cannot be empty");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		logger.info("OAuth2PushedAuthorizationRequestEndpointFilter");
		this.authenticationManager = authenticationManager;
		this.pushedAuthorizationRequestEndpointMatcher = createDefaultRequestMatcher(
				pushedAuthorizationRequestEndpointUri);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		System.out.println("OAuth2PushedAuthorizationRequestEndpointFilter:doFilterInternal");
		if (!this.pushedAuthorizationRequestEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}
		try {
			Authentication authentication = this.authenticationConverter.convert(request);
			if (authentication instanceof AbstractAuthenticationToken) {
				((AbstractAuthenticationToken) authentication)
						.setDetails(this.authenticationDetailsSource.buildDetails(request));
			}
			Authentication authenticationResult = this.authenticationManager.authenticate(authentication);
			if (!authenticationResult.isAuthenticated()) {
				// If the Principal (Resource Owner) is not authenticated then
				// pass through the chain with the expectation that the authentication process
				// will commence via AuthenticationEntryPoint
				filterChain.doFilter(request, response);
				return;
			}
			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authenticationResult);
		} catch (OAuth2AuthenticationException ex) {
			SecurityContextHolder.clearContext();
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Pushed Authorization Request request failed: %s", ex.getError()), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
	}

	private static RequestMatcher createDefaultRequestMatcher(String authorizationEndpointUri) {
		RequestMatcher pushedAuthorizationRequestRequestGetMatcher = new AntPathRequestMatcher(authorizationEndpointUri,
				HttpMethod.GET.name());
		RequestMatcher pushedAuthorizationRequestRequestPostMatcher = new AntPathRequestMatcher(
				authorizationEndpointUri, HttpMethod.POST.name());
		return new OrRequestMatcher(pushedAuthorizationRequestRequestGetMatcher,
				pushedAuthorizationRequestRequestPostMatcher);
	}

	private void sendPushedAuthorizationRequestResponse(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {
		OAuth2PushedAuthorizationRequestAuthenticationToken pushedAuthorizationRequestAuthentication = (OAuth2PushedAuthorizationRequestAuthenticationToken) authentication;
		OAuth2PushedAuthorizationRequest pushedAuthorizationRequest = pushedAuthorizationRequestAuthentication
				.getRequestClaims();
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.CREATED);
		this.pushedAuthorizationRequestHttpResponseConverter.write(pushedAuthorizationRequest, null, httpResponse);
	}

	private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException {
		OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
		this.errorHttpResponseConverter.write(error, null, httpResponse);
	}
	
	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
	 * to an instance of {@link OAuth2AuthorizationCodeRequestAuthenticationToken} or {@link OAuth2AuthorizationConsentAuthenticationToken}
	 * used for authenticating the request.
	 *
	 * @param authenticationConverter the {@link AuthenticationConverter} used when attempting to extract an Authorization Request (or Consent) from {@link HttpServletRequest}
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}
	
	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 * and returning the {@link OAuth2AuthorizationResponse Authorization Response}.
	 *
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 */
	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 * and returning the {@link OAuth2Error Error Response}.
	 *
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthorizationCodeRequestAuthenticationException}
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}
	
	public void setRequirePushedAuthorizationRequests(boolean requirePushedAuthorizationRequests) {
		this.requirePushedAuthorizationRequests = requirePushedAuthorizationRequests;
	}
}
