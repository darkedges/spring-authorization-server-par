package darkedges;

import java.security.Principal;
import java.util.Set;
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Pushed
 * Authorization Request used in the Authorization Code Grant.
 *
 * @author Nicholas Irving
 * @see OAuth2PushedAuthorizationRequestAuthenticationToken
 * @see OAuth2PushedAuthorizationRequestAuthenticationValidator
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 * @see <a target="_blank" href=
 *      "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1">Section
 *      4.1.1 Pushed Authorization Request</a>
 * @since 1.0.0
 */
public class OAuth2PushedAuthorizationRequestAuthenticationProvider implements AuthenticationProvider {
	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
	private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";
	private final Log logger = LogFactory.getLog(getClass());
	private final RegisteredClientRepository registeredClientRepository;
	private final OAuth2AuthorizationService authorizationService;
	private OAuth2TokenGenerator<OAuth2RequestUri> pushedAuthorizationRequestGenerator = new OAuth2PushedAuthorizationRequestGenerator();
	private Consumer<OAuth2PushedAuthorizationRequestAuthenticationContext> authenticationValidator = new OAuth2PushedAuthorizationRequestAuthenticationValidator();

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestAuthenticationProvider}
	 * using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService       the authorization service
	 */
	public OAuth2PushedAuthorizationRequestAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
	}

	private static OAuth2Authorization.Builder authorizationBuilder(RegisteredClient registeredClient,
			Authentication principal, OAuth2AuthorizationRequest authorizationRequest) {
		return OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(registeredClient.getClientName())
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.attribute(Principal.class.getName(), registeredClient)
				.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);
	}

	private static OAuth2TokenContext createPushedAuthorizationRequestTokenContext(
			OAuth2PushedAuthorizationRequestAuthenticationToken pushedAuthorizationRequestAuthentication,
			RegisteredClient registeredClient, OAuth2Authorization authorization, Set<String> authorizedScopes) {
		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal((Authentication) pushedAuthorizationRequestAuthentication.getPrincipal())
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.tokenType(new OAuth2TokenType(darkedges.OAuth2ParameterNames.REQUEST))
				.authorizedScopes(authorizedScopes)
				.authorizationGrant(pushedAuthorizationRequestAuthentication);
		// @formatter:on

		if (authorization != null) {
			tokenContextBuilder.authorization(authorization);
		}

		return tokenContextBuilder.build();
	}

	private static boolean isPrincipalAuthenticated(Authentication principal) {
		return principal != null && !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass())
				&& principal.isAuthenticated();
	}

	private static void throwError(String errorCode, String parameterName,
			OAuth2PushedAuthorizationRequestAuthenticationToken PushedAuthorizationRequestAuthentication,
			RegisteredClient registeredClient) {
		throwError(errorCode, parameterName, ERROR_URI, PushedAuthorizationRequestAuthentication, registeredClient,
				null);
	}

	private static void throwError(String errorCode, String parameterName, String errorUri,
			OAuth2PushedAuthorizationRequestAuthenticationToken PushedAuthorizationRequestAuthentication,
			RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
		throwError(error, parameterName, PushedAuthorizationRequestAuthentication, registeredClient,
				authorizationRequest);
	}

	private static void throwError(OAuth2Error error, String parameterName,
			OAuth2PushedAuthorizationRequestAuthenticationToken pushedAuthorizationRequestAuthentication,
			RegisteredClient registeredClient, OAuth2AuthorizationRequest authorizationRequest) {

		String redirectUri = resolveRedirectUri(authorizationRequest, registeredClient);
		if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_REQUEST)
				&& (parameterName.equals(OAuth2ParameterNames.CLIENT_ID)
						|| parameterName.equals(OAuth2ParameterNames.STATE))) {
			redirectUri = null; // Prevent redirects
		}
		OAuth2PushedAuthorizationRequestAuthenticationToken pushedAuthorizationRequestAuthenticationResult = new OAuth2PushedAuthorizationRequestAuthenticationToken(
				pushedAuthorizationRequestAuthentication.getAuthorizationUri(),
				pushedAuthorizationRequestAuthentication.getRegisteredClient(),
				(Authentication) pushedAuthorizationRequestAuthentication.getPrincipal(), redirectUri,
				pushedAuthorizationRequestAuthentication.getState(),
				pushedAuthorizationRequestAuthentication.getScopes(),
				pushedAuthorizationRequestAuthentication.getAdditionalParameters());

		throw new OAuth2PushedAuthorizationRequestAuthenticationException(error,
				pushedAuthorizationRequestAuthenticationResult);
	}

	private static String resolveRedirectUri(OAuth2AuthorizationRequest authorizationRequest,
			RegisteredClient registeredClient) {
		if (authorizationRequest != null && StringUtils.hasText(authorizationRequest.getRedirectUri())) {
			return authorizationRequest.getRedirectUri();
		}
		if (registeredClient != null) {
			return registeredClient.getRedirectUris().iterator().next();
		}
		return null;
	}

	/**
	 * Sets the {@link OAuth2TokenGenerator} that generates the
	 * {@link OAuth2RequestUri}.
	 *
	 * @param pushedAuthorizationRequestGenerator the {@link OAuth2TokenGenerator}
	 *                                            that generates the
	 *                                            {@link OAuth2RequestUri}
	 * @since 1.0.0
	 */
	public void setPushedAuthorizationRequestGenerator(
			OAuth2TokenGenerator<OAuth2RequestUri> pushedAuthorizationRequestGenerator) {
		Assert.notNull(pushedAuthorizationRequestGenerator, "pushedAuthorizationRequestGenerator cannot be null");
		this.pushedAuthorizationRequestGenerator = pushedAuthorizationRequestGenerator;
	}

	/**
	 * Sets the {@code Consumer} providing access to the
	 * {@link OAuth2PushedAuthorizationRequestAuthenticationContext} and is
	 * responsible for validating specific OAuth 2.0 Authorization Request
	 * parameters associated in the
	 * {@link OAuth2PushedAuthorizationRequestAuthenticationToken}. The default
	 * authentication validator is
	 * {@link OAuth2PushedAuthorizationRequestAuthenticationValidator}.
	 *
	 * <p>
	 * <b>NOTE:</b> The authentication validator MUST throw
	 * {@link OAuth2PushedAuthorizationRequestAuthenticationException} if validation
	 * fails.
	 *
	 * @param authenticationValidator the {@code Consumer} providing access to the
	 *                                {@link OAuth2PushedAuthorizationRequestAuthenticationContext}
	 *                                and is responsible for validating specific
	 *                                OAuth 2.0 Authorization Request parameters
	 * @since 0.4.0
	 */
	public void setAuthenticationValidator(
			Consumer<OAuth2PushedAuthorizationRequestAuthenticationContext> authenticationValidator) {
		Assert.notNull(authenticationValidator, "authenticationValidator cannot be null");
		this.authenticationValidator = authenticationValidator;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2PushedAuthorizationRequestAuthenticationToken pushedAuthorizationRequestAuthentication = (OAuth2PushedAuthorizationRequestAuthenticationToken) authentication;

		RegisteredClient registeredClient = this.registeredClientRepository
				.findByClientId(pushedAuthorizationRequestAuthentication.getRegisteredClient().getClientId());
		if (registeredClient == null) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID,
					pushedAuthorizationRequestAuthentication, null);
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}
		OAuth2PushedAuthorizationRequestAuthenticationContext authenticationContext = OAuth2PushedAuthorizationRequestAuthenticationContext
				.with(pushedAuthorizationRequestAuthentication).registeredClient(registeredClient).build();
		this.authenticationValidator.accept(authenticationContext);
		// code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
		String codeChallenge = (String) pushedAuthorizationRequestAuthentication.getAdditionalParameters()
				.get(PkceParameterNames.CODE_CHALLENGE);
		if (StringUtils.hasText(codeChallenge)) {
			String codeChallengeMethod = (String) pushedAuthorizationRequestAuthentication.getAdditionalParameters()
					.get(PkceParameterNames.CODE_CHALLENGE_METHOD);
			if (!StringUtils.hasText(codeChallengeMethod) || !"S256".equals(codeChallengeMethod)) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, PKCE_ERROR_URI,
						pushedAuthorizationRequestAuthentication, registeredClient, null);
			}
		} else if (registeredClient.getClientSettings().isRequireProofKey()) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI,
					pushedAuthorizationRequestAuthentication, registeredClient, null);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated pushed authorization request parameters");
		}

		// ---------------
		// The request is valid - ensure the resource owner is authenticated
		// ---------------

		Authentication principal = (Authentication) pushedAuthorizationRequestAuthentication.getPrincipal();
		if (!isPrincipalAuthenticated(principal)) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Did not authenticate pushed authorization request since principal not authenticated");
			}
			// Return the authorization request as-is where isAuthenticated() is false
			return pushedAuthorizationRequestAuthentication;
		}

		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(pushedAuthorizationRequestAuthentication.getAuthorizationUri())
				.clientId(registeredClient.getClientId())
				.redirectUri(pushedAuthorizationRequestAuthentication.getRedirectUri())
				.scopes(pushedAuthorizationRequestAuthentication.getScopes())
				.state(pushedAuthorizationRequestAuthentication.getState())
				.additionalParameters(pushedAuthorizationRequestAuthentication.getAdditionalParameters()).build();

		OAuth2TokenContext tokenContext = createPushedAuthorizationRequestTokenContext(
				pushedAuthorizationRequestAuthentication, registeredClient, null, authorizationRequest.getScopes());
		OAuth2RequestUri requestUri = this.pushedAuthorizationRequestGenerator.generate(tokenContext);
		if (requestUri == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the request uri.", ERROR_URI);
			throw new OAuth2PushedAuthorizationRequestAuthenticationException(error, null);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Generated authorization code");
		}
		OAuth2Authorization authorization = authorizationBuilder(registeredClient, null, authorizationRequest)
				.authorizedScopes(authorizationRequest.getScopes()).token(requestUri).build();
		this.authorizationService.save(authorization);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved authorization");
		}
		String redirectUri = authorizationRequest.getRedirectUri();
		if (!StringUtils.hasText(redirectUri)) {
			redirectUri = registeredClient.getRedirectUris().iterator().next();
		}
		OAuth2PushedAuthorizationRequest requestClaims = OAuth2PushedAuthorizationRequest.builder()
				.requestUri(requestUri.getTokenValue()).expiresIn(60).build();
		return new OAuth2PushedAuthorizationRequestAuthenticationToken(authorizationRequest.getAuthorizationUri(),
				registeredClient, principal, requestClaims, redirectUri, authorizationRequest.getState(),
				authorizationRequest.getScopes(), requestUri);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2PushedAuthorizationRequestAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
