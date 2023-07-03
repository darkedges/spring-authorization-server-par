package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2PushedAuthorizationRequestEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import darkedges.JwtPushedAuthorizationRequestDecoderFactory;
import darkedges.OAuth2PushedAuthorizationRequestAuthenticationContext;
import darkedges.OAuth2PushedAuthorizationRequestAuthenticationConverter;
import darkedges.OAuth2PushedAuthorizationRequestAuthenticationProvider;
import darkedges.OAuth2PushedAuthorizationRequestAuthenticationValidator;

public class OAuth2PushedAuthorizationRequestEndpointConfigurer
		extends AbstractHttpConfigurer<OAuth2PushedAuthorizationRequestEndpointConfigurer, HttpSecurity> {
	private RequestMatcher endpointsMatcher;
	private AuthenticationSuccessHandler authorizationResponseHandler;
	private AuthenticationFailureHandler errorResponseHandler;
	private final Log logger = LogFactory.getLog(getClass());
	private boolean requirePushedAuthorizationRequests;
	private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
	private final List<AuthenticationConverter> authorizationRequestConverters = new ArrayList<>();
	private final Consumer<List<AuthenticationConverter>> authorizationRequestConvertersConsumer = (
			authorizationRequestConverters) -> {
	};
	private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {
	};
	private Consumer<OAuth2PushedAuthorizationRequestAuthenticationContext> pushedAuthorizationRequestAuthenticationValidator;

	public OAuth2PushedAuthorizationRequestEndpointConfigurer() {
		// @formatter:off
		this.endpointsMatcher = new OrRequestMatcher(
				new AntPathRequestMatcher(
						OAuth2PushedAuthorizationRequestEndpointFilter.DEFAULT_PUSHED_AUTHORIZATION_REQUEST_ENDPOINT_URI,
						HttpMethod.GET.name()
				),
				new AntPathRequestMatcher(
						OAuth2PushedAuthorizationRequestEndpointFilter.DEFAULT_PUSHED_AUTHORIZATION_REQUEST_ENDPOINT_URI,
						HttpMethod.POST.name()
				)
		);
		// @formatter:on
	}

	@Override
	public void init(HttpSecurity httpSecurity) throws Exception {
		List<AuthenticationProvider> authenticationProviders = createDefaultAuthenticationProviders(httpSecurity);
		if (!this.authenticationProviders.isEmpty()) {
			authenticationProviders.addAll(0, this.authenticationProviders);
		}
		this.authenticationProvidersConsumer.accept(authenticationProviders);
		authenticationProviders.forEach(
				authenticationProvider -> httpSecurity.authenticationProvider(postProcess(authenticationProvider)));
	}

	@Override
	public void configure(HttpSecurity httpSecurity) throws Exception {
		logger.info("OAuth2PushedAuthorizationRequestEndpointConfigurer:configure");
		AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
		OAuth2ClientAuthenticationFilter clientAuthenticationFilter = new OAuth2ClientAuthenticationFilter(
				authenticationManager, this.endpointsMatcher);
		OAuth2PushedAuthorizationRequestEndpointFilter pushedAuthorizationRequestEndpointFilter = new OAuth2PushedAuthorizationRequestEndpointFilter(
				authenticationManager,
				OAuth2PushedAuthorizationRequestEndpointFilter.DEFAULT_PUSHED_AUTHORIZATION_REQUEST_ENDPOINT_URI);
		List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters(httpSecurity);
		if (!this.authorizationRequestConverters.isEmpty()) {
			authenticationConverters.addAll(0, this.authorizationRequestConverters);
		}
		this.authorizationRequestConvertersConsumer.accept(authenticationConverters);
		pushedAuthorizationRequestEndpointFilter
				.setAuthenticationConverter(new DelegatingAuthenticationConverter(authenticationConverters));
		if (this.authorizationResponseHandler != null) {
			pushedAuthorizationRequestEndpointFilter.setAuthenticationSuccessHandler(this.authorizationResponseHandler);
		}
		if (this.errorResponseHandler != null) {
			pushedAuthorizationRequestEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
		}
		pushedAuthorizationRequestEndpointFilter
				.setRequirePushedAuthorizationRequests(this.requirePushedAuthorizationRequests);
		httpSecurity.addFilterAfter(postProcess(clientAuthenticationFilter), AbstractPreAuthenticatedProcessingFilter.class);
		httpSecurity.addFilterAfter(postProcess(pushedAuthorizationRequestEndpointFilter),
				AbstractPreAuthenticatedProcessingFilter.class);
		System.out.println(pushedAuthorizationRequestEndpointFilter);
	}

	private static List<AuthenticationConverter> createDefaultAuthenticationConverters(HttpSecurity httpSecurity) {
		List<AuthenticationConverter> authenticationConverters = new ArrayList<>();
		RegisteredClientRepository registeredClientRepository = OAuth2ConfigurerUtils
				.getRegisteredClientRepository(httpSecurity);
		JwtDecoderFactory<RegisteredClient> jwtDecoderFactory = new JwtPushedAuthorizationRequestDecoderFactory();
		authenticationConverters.add(new OAuth2PushedAuthorizationRequestAuthenticationConverter(
				registeredClientRepository, jwtDecoderFactory));
		
		return authenticationConverters;
	}

	/**
	 * Returns a {@link RequestMatcher} for the authorization server endpoints.
	 *
	 * @return a {@link RequestMatcher} for the authorization server endpoints
	 */
	public RequestMatcher getEndpointsMatcher() {
		// Return a deferred RequestMatcher
		// since endpointsMatcher is constructed in init(HttpSecurity).
		return (request) -> this.endpointsMatcher.matches(request);
	}

	private List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
		List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
		OAuth2PushedAuthorizationRequestAuthenticationProvider pushedAuthorizationRequestAuthenticationProvider = new OAuth2PushedAuthorizationRequestAuthenticationProvider(
				OAuth2ConfigurerUtils.getRegisteredClientRepository(httpSecurity),
				OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity));
		if (this.pushedAuthorizationRequestAuthenticationValidator != null) {
			pushedAuthorizationRequestAuthenticationProvider
					.setAuthenticationValidator(new OAuth2PushedAuthorizationRequestAuthenticationValidator()
							.andThen(this.pushedAuthorizationRequestAuthenticationValidator));
		}
		authenticationProviders.add(pushedAuthorizationRequestAuthenticationProvider);
		return authenticationProviders;
	}
}
