package org.appng.application.authentication.saml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.appng.api.Environment;
import org.appng.api.model.Application;
import org.appng.api.model.Subject;
import org.appng.core.service.CoreService;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
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

	private final Application application;
	private final CoreService coreService;

	private @Value("${samlEnabled:false}") boolean samlEnabled;
	private @Value("${samlClientId:}") String clientId;
	private @Value("${samlAssertionConsumerUrl:}") String assertionConsumerUrl;
	private SamlClient samlClient;

	@Override
	public void afterPropertiesSet() throws Exception {
		if (samlEnabled) {
			byte[] samlDescriptor = application.getProperties().getClob("samlDescriptor")
					.getBytes(StandardCharsets.UTF_8);
			samlClient = SamlClient.fromMetadata(clientId, assertionConsumerUrl,
					new InputStreamReader(new ByteArrayInputStream(samlDescriptor)), SamlClient.SamlIdpBinding.POST);
			LOGGER.debug("Created SAML client for '' with endpoint {}", clientId, assertionConsumerUrl);
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

	@PostMapping(path = "/saml", produces = { MediaType.TEXT_PLAIN_VALUE }, consumes = { MediaType.TEXT_PLAIN_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public ResponseEntity<Void> reply(HttpServletRequest request, Environment environment) {
		if (!samlEnabled) {
			return NOT_IMPLEMENTED;
		}
		ResponseEntity<Void> response = new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
		try {
			String parameter = request.getParameter("SAMLResponse");
			LOGGER.debug("Received SAMLResponse: {}", parameter);
			SamlResponse samlResp = samlClient.decodeAndValidateSamlResponse(parameter, request.getMethod());

			Assertion assertion = samlResp.getAssertion();

			Map<String, List<String>> stringAttributes = new HashMap<>();

			for (AttributeStatement as : assertion.getAttributeStatements()) {
				for (Attribute attr : as.getAttributes()) {
					String name = attr.getName();
					List<String> values = attr.getAttributeValues().stream().filter(v -> (v instanceof XSString))
							.map(XSString.class::cast).map(XSString::getValue).collect(Collectors.toList());
					stringAttributes.put(name, values);
					LOGGER.debug("Attribute {} with values {}", name, StringUtils.join(values, ", "));
				}
			}

			// https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-saml-tokens

			String emailAttributeName = "Email";
			List<String> emails = stringAttributes.get(emailAttributeName);
			if (!emails.isEmpty()) {
				String email = emails.get(0);
				Subject subject = coreService.getSubjectByEmail(email);
				if (null == subject) {
					// TODO create subject with basic user group?

				} else {
					coreService.loginByUserName(environment, subject.getAuthName());
					HttpHeaders headers = new HttpHeaders();
					// TODO forward to certain application
					headers.set(HttpHeaders.LOCATION, "/manager");
					response = new ResponseEntity<>(headers, HttpStatus.FOUND);
				}
			}

		} catch (SamlException e) {
			LOGGER.error("Error processing SAML Response", e);
			response = new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
		}
		return response;
	}

}