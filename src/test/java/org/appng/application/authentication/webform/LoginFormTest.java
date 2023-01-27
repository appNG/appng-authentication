/*
 * Copyright 2011-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.appng.application.authentication.webform;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

import org.appng.api.Platform;
import org.appng.api.Scope;
import org.appng.api.Session;
import org.appng.api.SiteProperties;
import org.appng.api.model.Property;
import org.appng.api.model.SimpleProperty;
import org.appng.api.model.Subject;
import org.appng.application.authentication.AuthenticationSettings;
import org.appng.testsupport.TestBase;
import org.junit.Assert;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.ContextConfiguration;

@ContextConfiguration(locations = { TestBase.TESTCONTEXT_JPA,
		TestBase.TESTCONTEXT_CORE }, initializers = LoginFormTest.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@DirtiesContext(classMode = ClassMode.AFTER_EACH_TEST_METHOD)
public class LoginFormTest extends TestBase {

	public LoginFormTest() {
		super("appng-authentication", "application-home");
		setEntityPackage("org.appng.core.domain");
		setRepositoryBase("org.appng.core.repository");
	}

	@Before
	public void setup() throws Exception {
		super.setup();
		environment.removeAttribute(Scope.SESSION, Session.Environment.SUBJECT);
	}

	@Test
	public void test() {
		context.getBean(LoginForm.class).getData(site, application, environment, null, request, null);
		Assert.assertEquals(Locale.ENGLISH.getLanguage(), environment.getSubject().getLanguage());
		Assert.assertEquals(Locale.ENGLISH, environment.getLocale());
	}

	@Test
	public void testFromSubject() {
		Subject mock = Mockito.mock(Subject.class);
		environment.setAttribute(Scope.SESSION, Session.Environment.SUBJECT, mock);
		Mockito.when(mock.getLanguage()).thenReturn(Locale.GERMAN.getLanguage());
		context.getBean(LoginForm.class).getData(site, application, environment, null, request, null);
		Assert.assertEquals(Locale.GERMAN.getLanguage(), environment.getSubject().getLanguage());
		Assert.assertEquals(Locale.ENGLISH, environment.getLocale());
	}

	@Test
	public void testRedirect() {
		addParameter("action", "login");
		initParameters();
		context.getBean(LoginForm.class).getData(site, application, environment, null, request, null);
		Assert.assertEquals(Locale.ENGLISH.getLanguage(), environment.getSubject().getLanguage());
		Assert.assertEquals(Locale.ENGLISH, environment.getLocale());
		Mockito.verify(site).sendRedirect(Mockito.eq(environment), Mockito.eq("?action=login"));
	}

	@Test
	public void testSiteDefault() {
		servletRequest.setPreferredLocales(Arrays.asList(Locale.ITALIAN, Locale.FRENCH));
		addParameter("action", "login");
		initParameters();
		context.getBean(LoginForm.class).getData(site, application, environment, null, request, null);
		Assert.assertEquals(Locale.ENGLISH.getLanguage(), environment.getSubject().getLanguage());
		Assert.assertEquals(Locale.ENGLISH, environment.getLocale());
		Mockito.verify(site).sendRedirect(Mockito.eq(environment), Mockito.eq("?action=login"));
	}

	@Test
	public void testViaUrl() {
		addParameter("lang", "de");
		initParameters();
		context.getBean(LoginForm.class).getData(site, application, environment, null, request, null);
		Assert.assertEquals(Locale.GERMAN.getLanguage(), environment.getSubject().getLanguage());
		Assert.assertEquals(Locale.GERMAN, environment.getLocale());
	}

	@Test
	public void testViaUrlInvalidLang() {
		addParameter("lang", "fr");
		initParameters();
		context.getBean(LoginForm.class).getData(site, application, environment, null, request, null);
		Assert.assertEquals(Locale.ENGLISH.getLanguage(), environment.getSubject().getLanguage());
		Assert.assertEquals(Locale.ENGLISH, environment.getLocale());
	}

	@Override
	protected List<Property> getPlatformProperties(String prefix) {
		List<Property> platformProperties = super.getPlatformProperties(prefix);
		platformProperties.add(new SimpleProperty(prefix + Platform.Property.APPNG_DATA, "."));
		// JDK-8254876 first segment of Path must exist!
		new File("target/uploads").mkdirs();
		return platformProperties;
	}

	@Override
	protected List<Property> getSiteProperties(String prefix) {
		List<Property> siteProperties = super.getSiteProperties(prefix);
		siteProperties.add(new SimpleProperty(prefix + SiteProperties.SUPPORTED_LANGUAGES, "en,de"));
		return siteProperties;
	}

	@Override
	protected Properties getProperties() {
		Properties props = super.getProperties();
		props.put(AuthenticationSettings.SAML_ENABLED, "false");
		props.put(AuthenticationSettings.SAML_CLIENT_ID, "");
		props.put(AuthenticationSettings.SAML_FORWARD_TARGET, "");
		return props;
	}

}
