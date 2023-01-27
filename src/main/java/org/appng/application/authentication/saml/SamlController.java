package org.appng.application.authentication.saml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.appng.api.BusinessException;
import org.appng.api.Environment;
import org.appng.api.model.Application;
import org.appng.api.model.Group;
import org.appng.api.model.AuthSubject.PasswordChangePolicy;
import org.appng.api.model.Site;
import org.appng.api.model.Subject;
import org.appng.api.model.UserType;
import org.appng.api.support.ElementHelper;
import org.appng.application.authentication.AbstractLogon;
import org.appng.application.authentication.AuthenticationSettings;
import org.appng.application.authentication.MessageConstants;
import org.appng.core.domain.SubjectImpl;
import org.appng.core.service.CoreService;
import org.appng.tools.ui.StringNormalizer;
import org.appng.xml.platform.Message;
import org.appng.xml.platform.MessageType;
import org.appng.xml.platform.Messages;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.coveo.saml.SamlClient;
import com.coveo.saml.SamlException;
import com.coveo.saml.SamlResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * <a href="https://learn.microsoft.com/en-us/azure/active-directory/develop/single-sign-on-saml-protocol"><img alt=
 * "smal-workflow" src=
 * "https://learn.microsoft.com/en-us/azure/active-directory/develop/media/single-sign-on-saml-protocol/active-directory-saml-single-sign-on-workflow.png"
 * /></a><br/>
 * <br/>
 * <a href= "https://learn.microsoft.com/de-de/azure/active-directory/fundamentals/auth-saml"><img alt="SAML Auth" src=
 * "https://learn.microsoft.com/de-de/azure/active-directory/fundamentals/media/authentication-patterns/saml-auth.png"
 * /></a>
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@SuppressWarnings("unchecked")
public class SamlController implements InitializingBean {

	@SuppressWarnings("rawtypes")
	private static final ResponseEntity NOT_IMPLEMENTED = ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).build();

	private final Site site;
	private final Application application;
	private final CoreService coreService;
	private final MessageSource messageSource;

	private @Value("${" + AuthenticationSettings.SAML_ENABLED + "}") boolean samlEnabled;
	private @Value("${" + AuthenticationSettings.SAML_CLIENT_ID + "}") String clientId;
	private @Value("${" + AuthenticationSettings.SAML_FORWARD_TARGET + "}") String forwardTarget;
	private List<String> userGroups;
	private SamlClient samlClient;
	private String ssoEndpoint;

	public static String CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/";

	@Override
	public void afterPropertiesSet() throws Exception {
		if (samlEnabled) {
			byte[] samlDescriptor = application.getProperties().getClob(AuthenticationSettings.SAML_DESCRIPTOR)
					.getBytes(StandardCharsets.UTF_8);
			userGroups = application.getProperties().getList(AuthenticationSettings.SAML_CREATE_NEW_USER_WITH_GROUPS,
					",");
			ssoEndpoint = String.format("%s/service/%s/%s/rest/saml", site.getDomain(), site.getName(),
					application.getName());
			samlClient = SamlClient.fromMetadata(clientId, ssoEndpoint,
					new InputStreamReader(new ByteArrayInputStream(samlDescriptor)), SamlClient.SamlIdpBinding.POST);
			LOGGER.info("Created SAML client '{}' with endpoint {}", clientId, samlClient.getIdentityProviderUrl());
		} else {
			LOGGER.debug("SAML is disabled");
		}
	}

	@GetMapping(path = { "/saml", "/saml/login" }, produces = MediaType.TEXT_HTML_VALUE)
	public void login(HttpServletResponse response) throws IOException, SamlException {
		if (!samlEnabled) {
			response.setStatus(NOT_IMPLEMENTED.getStatusCodeValue());
			return;
		}
		samlClient.redirectToIdentityProvider(response, null);
	}

	@PostMapping(path = "/saml", produces = MediaType.TEXT_PLAIN_VALUE, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
	public ResponseEntity<Void> reply(HttpServletRequest request, Environment environment) {
		if (!samlEnabled) {
			return NOT_IMPLEMENTED;
		}
		String messageText = MessageConstants.USER_LOGIN_FAIL;
		MessageType level = MessageType.ERROR;
		String target = forwardTarget;
		try {
			String parameter = request.getParameter("SAMLResponse");
			SamlResponse samlResp = samlClient.decodeAndValidateSamlResponse(parameter, request.getMethod());
			String email = samlResp.getNameID();
			LOGGER.debug("Received SAMLResponse for {}", email);

			Assertion assertion = samlResp.getAssertion();
			Map<String, List<String>> attributes = new HashMap<>();

			for (AttributeStatement as : assertion.getAttributeStatements()) {
				for (Attribute attr : as.getAttributes()) {
					String name = attr.getName();
					List<String> values = attr.getAttributeValues().stream().filter(v -> (v instanceof AttributeValue))
							.map(AttributeValue.class::cast).map(AttributeValue::getTextContent)
							.collect(Collectors.toList());
					attributes.put(name, values);
					LOGGER.debug("Attribute {} with values {}", name, StringUtils.join(values, ", "));
				}
			}

			// https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-saml-tokens
			Subject subject = coreService.getSubjectByEmail(email);
			if (null == subject && !userGroups.isEmpty()) {
				subject = createUser(environment, email, attributes);
			}

			if (null != subject) {
				if (subject.isLocked()) {
					messageText = MessageConstants.USER_IS_LOCKED;
				} else {
					boolean success = coreService.loginByUserName(environment, subject.getAuthName());
					LOGGER.info("Logged in {} : {}", subject.getAuthName(), success);
					if (success) {
						messageText = MessageConstants.USER_AUTHENTICATED;
						level = MessageType.OK;
						List<String> groupNames = environment.getSubject().getGroups().stream().map(Group::getName)
								.collect(Collectors.toList());
						target = AbstractLogon.getSuccessPage(application.getProperties(), success, groupNames);
					}
				}
			} else {
				messageText = MessageConstants.USER_UNKNOWN;
				level = MessageType.INVALID;
			}

		} catch (SamlException e) {
			LOGGER.error("Error processing SAML Response", e);
		}
		Messages messages = new Messages();
		Message message = new Message();
		message.setClazz(level);
		message.setContent(messageSource.getMessage(messageText, new Object[0], environment.getLocale()));
		messages.getMessageList().add(message);
		ElementHelper.addMessages(environment, messages);

		HttpHeaders headers = new HttpHeaders();
		headers.set(HttpHeaders.LOCATION, target);
		LOGGER.info("Forwarding to {}", target);
		return new ResponseEntity<>(headers, HttpStatus.FOUND);
	}

	private Subject createUser(Environment environment, String email, Map<String, List<String>> attributes) {
		String givenname = attributes.get(CLAIM + "givenname").get(0);
		String surname = attributes.get(CLAIM + "surname").get(0);
		String userName = StringUtils.lowerCase(StringNormalizer.normalize(givenname + "." + surname));
		try {
			SubjectImpl user = new SubjectImpl();
			user.setEmail(email);
			user.setLanguage(environment.getLocale().getLanguage());
			user.setName(userName);
			user.setTimeZone(environment.getTimeZone().getID());
			user.setPasswordChangePolicy(PasswordChangePolicy.MUST_NOT);
			user.setRealname(givenname + " " + surname);
			user.setDescription("automatically created from SAML login at " + new Date());
			user.setUserType(UserType.LOCAL_USER);
			Subject newUser = coreService.createSubject(user);
			coreService.addGroupsToSubject(user.getName(), userGroups, true);
			LOGGER.info("Created user {} with group(s)", userName, StringUtils.join(userGroups, ", "));
			return newUser;
		} catch (BusinessException e) {
			LOGGER.error("Error creating new user " + userName, e);
		}
		return null;
	}

	@PostMapping(path = "/saml/sign-on", produces = { MediaType.TEXT_PLAIN_VALUE }, consumes = {
			MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_XML_VALUE })
	public ResponseEntity<String> signOn(@RequestBody String payload) {
		if (!samlEnabled) {
			return NOT_IMPLEMENTED;
		}
		return new ResponseEntity<>(payload, HttpStatus.OK);
	}

	@PostMapping(path = "/saml/logout", produces = { MediaType.TEXT_PLAIN_VALUE }, consumes = {
			MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_XML_VALUE })
	public ResponseEntity<String> logout(@RequestBody String payload) {
		if (!samlEnabled) {
			return NOT_IMPLEMENTED;
		}
		return new ResponseEntity<>(payload, HttpStatus.OK);
	}

	public boolean isEnabled() {
		return samlEnabled;
	}

	public String getEndpoint() {
		return ssoEndpoint;
	}

}