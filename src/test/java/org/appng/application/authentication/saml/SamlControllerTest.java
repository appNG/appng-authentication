package org.appng.application.authentication.saml;

import java.util.Arrays;
import java.util.Locale;
import java.util.TimeZone;

import org.appng.api.Environment;
import org.appng.api.Scope;
import org.appng.api.model.Application;
import org.appng.api.model.Site;
import org.appng.api.model.Subject;
import org.appng.application.authentication.AbstractLogon;
import org.appng.core.service.CoreService;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import com.coveo.saml.SamlClient;
import com.coveo.saml.SamlResponse;

public class SamlControllerTest {

	@Test
	public void test() throws Exception {
		Site site = Mockito.mock(Site.class);
		Application app = Mockito.mock(Application.class);
		CoreService service = Mockito.mock(CoreService.class);
		MessageSource messageSource = Mockito.mock(MessageSource.class);

		SamlController samlController = new SamlController(site, app, service, messageSource) {
			@Override
			public void afterPropertiesSet() throws Exception {
				samlEnabled = true;
				userGroups = Arrays.asList("User");
				samlClient = Mockito.mock(SamlClient.class);

				SamlResponse saml = Mockito.mock(SamlResponse.class);
				Mockito.when(samlClient.decodeAndValidateSamlResponse(Mockito.any(), Mockito.any())).thenReturn(saml);
				Assertion assertion = Mockito.mock(Assertion.class);
				Mockito.when(saml.getAssertion()).thenReturn(assertion);
				Mockito.when(saml.getNameID()).thenReturn("kirk@enter.prise");

				AttributeStatement statement = Mockito.mock(AttributeStatement.class);
				Mockito.when(assertion.getAttributeStatements()).thenReturn(Arrays.asList(statement));

				Attribute attribute = Mockito.mock(Attribute.class);
				Mockito.when(statement.getAttributes()).thenReturn(Arrays.asList(attribute, attribute));
				Mockito.when(attribute.getName()).thenReturn(CLAIM + SAML_GIVENNAME, CLAIM + SAML_SURNAME);
				AttributeValue value = Mockito.mock(AttributeValue.class);
				Mockito.when(attribute.getAttributeValues()).thenReturn(Arrays.asList(value));
				Mockito.when(value.getTextContent()).thenReturn("Kirk", "James T.");
			}
		};

		samlController.afterPropertiesSet();

		MockHttpServletRequest request = new MockHttpServletRequest();
		Environment env = Mockito.mock(Environment.class);
		Mockito.when(service.loginByUserName(env, "kirk.jamest.")).thenReturn(true);
		Mockito.when(env.getLocale()).thenReturn(Locale.ENGLISH);
		Mockito.when(env.getTimeZone()).thenReturn(TimeZone.getTimeZone("UTC"));
		String preLogin = "/path/to/app";
		Mockito.when(env.getAttribute(Scope.SESSION, AbstractLogon.PRE_LOGIN_PATH)).thenReturn(preLogin);
		Mockito.doAnswer(i -> i.getArgumentAt(0, Subject.class)).when(service).createSubject(Mockito.any());

		ResponseEntity<Void> response = samlController.reply(request, env);

		Assert.assertEquals(HttpStatus.FOUND, response.getStatusCode());
		Assert.assertEquals(preLogin, response.getHeaders().getLocation().toString());
	}

}
