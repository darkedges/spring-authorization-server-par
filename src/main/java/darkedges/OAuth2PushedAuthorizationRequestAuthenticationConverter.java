package darkedges;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.web.OAuth2PushedAuthorizationRequestEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Attempts to extract an Pushed Authorization Request from
 * {@link HttpServletRequest} and then converts it to an
 * {@link OAuth2PushedAuthorizationRequestAuthenticationToken} used for
 * authenticating the request.
 *
 * @author Nicholas Irving
 * @see AuthenticationConverter
 * @see OAuth2PushedAuthorizationRequestAuthenticationToken
 * @see OAuth2PushedAuthorizationRequestEndpointFilter
 * @since 1.0.0
 */
public class OAuth2PushedAuthorizationRequestAuthenticationConverter implements AuthenticationConverter {
	private static final String ERROR_URI = "https://www.rfc-editor.org/rfc/rfc9126#name-error-response";
	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous",
			"anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
	private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";

	private final Log logger = LogFactory.getLog(getClass());
	private final JwtDecoderFactory<RegisteredClient> jwtDecoderFactory;
	private final RegisteredClientRepository registeredClientRepository;

	public OAuth2PushedAuthorizationRequestAuthenticationConverter(
			RegisteredClientRepository registeredClientRepository,
			JwtDecoderFactory<RegisteredClient> jwtDecoderFactory) {
		this.registeredClientRepository = registeredClientRepository;
		this.jwtDecoderFactory = jwtDecoderFactory;
	}

	@Override
	public Authentication convert(HttpServletRequest httpServletRequest) {
		
		String authorizationUri = httpServletRequest.getRequestURL().toString();

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(httpServletRequest);

		// request (REQUIRED)
		String request = parameters.getFirst(darkedges.OAuth2ParameterNames.REQUEST);
		if (!StringUtils.hasText(request) || parameters.get(darkedges.OAuth2ParameterNames.REQUEST).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, darkedges.OAuth2ParameterNames.REQUEST);
		}

		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (principal == null) {
			principal = ANONYMOUS_AUTHENTICATION;
		}

		// client_id (REQUIRED)
		String clientId = FAPIUtil.getClientId(request);
		if (!StringUtils.hasText(clientId)) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
		}
		// Lookup the client and validate the request
		RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
		}
		Jwt jwtAssertion = null;
		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(registeredClient);
		try {
			jwtAssertion = jwtDecoder.decode(request);
		} catch (JwtException ex) {
			throwInvalidPushedAuthorizationRequest(darkedges.OAuth2ParameterNames.REQUEST, ex);
		}

		// response_type (REQUIRED)
		String responseType = jwtAssertion.getClaimAsString(OAuth2ParameterNames.RESPONSE_TYPE);
		if (!StringUtils.hasText(responseType)) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.RESPONSE_TYPE);
		} else if (!responseType.contains(OAuth2AuthorizationResponseType.CODE.getValue())) {
			throwError(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, OAuth2ParameterNames.RESPONSE_TYPE);
		}

		if (registeredClient.getClientSettings().isRequireProofKey()) {
			// code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
			String codeChallenge = jwtAssertion.getClaimAsString(PkceParameterNames.CODE_CHALLENGE);
			if (!StringUtils.hasText(codeChallenge)) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI);
			}

			// code_challenge_method (OPTIONAL for public clients) - RFC 7636 (PKCE)
			String codeChallengeMethod = jwtAssertion.getClaimAsString(PkceParameterNames.CODE_CHALLENGE_METHOD);
			if (!StringUtils.hasText(codeChallengeMethod)) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, PKCE_ERROR_URI);
			}
		}

		// scope (REQUIRED)
		Set<String> scopes = null;
		String scope = jwtAssertion.getClaimAsString(OAuth2ParameterNames.SCOPE);
		if (!StringUtils.hasText(scope)) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE);
		} else {
			scopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}

		// state (REQUIRED)
		String state = jwtAssertion.getClaimAsString(OAuth2ParameterNames.STATE);
		if (!StringUtils.hasText(state)) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
		}

		// redirect_uri (REQUIRED)
		String redirectUri = jwtAssertion.getClaimAsString(OAuth2ParameterNames.REDIRECT_URI);
		if (!StringUtils.hasText(redirectUri)) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI);
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(darkedges.OAuth2ParameterNames.REQUEST) && !key.equals(OAuth2ParameterNames.CLIENT_ID)
					&& !key.equals(OAuth2ParameterNames.SCOPE) && !key.equals(OAuth2ParameterNames.STATE)
					&& !key.equals(OAuth2ParameterNames.REDIRECT_URI)) {
				additionalParameters.put(key, value.get(0));
			}
		});
		jwtAssertion.getClaims().forEach((key, value) -> {
			if (!key.equals(darkedges.OAuth2ParameterNames.REQUEST) && !key.equals(OAuth2ParameterNames.CLIENT_ID)) {
				additionalParameters.put(key, value);
			}
		});

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated client authentication parameters");
		}
		return new OAuth2PushedAuthorizationRequestAuthenticationToken(authorizationUri, registeredClient,principal,
				redirectUri, state, scopes, additionalParameters);
	}

	private static void throwInvalidPushedAuthorizationRequest(String parameterName) {
		throwInvalidPushedAuthorizationRequest(parameterName, null);
	}

	private static void throwInvalidPushedAuthorizationRequest(String parameterName, Throwable cause) {
		OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
				"Pushed Authorization Request decode failed: " + parameterName, ERROR_URI);
		throw new OAuth2AuthenticationException(error, error.toString(), cause);
	}

	private static void throwError(String errorCode, String parameterName) {
		throwError(errorCode, parameterName, DEFAULT_ERROR_URI);
	}

	private static void throwError(String errorCode, String parameterName, String errorUri) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
		throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
	}

}
