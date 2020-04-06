/*
 * Copyright 2011-2020 the original author or authors.
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

import java.util.ArrayList;
import java.util.List;

import org.appng.api.ProcessingException;
import org.appng.api.model.Property;
import org.appng.api.model.SimpleProperty;
import org.appng.api.support.CallableAction;
import org.appng.api.support.PropertyHolder;
import org.appng.application.authentication.BaseLoginTest;
import org.appng.core.security.ConfigurablePasswordPolicy;
import org.appng.core.service.PropertySupport;
import org.appng.testsupport.validation.WritingXmlValidator;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.MethodMode;
import org.springframework.transaction.annotation.Transactional;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@DirtiesContext(methodMode = MethodMode.AFTER_METHOD)
public class PasswordChangeTest extends BaseLoginTest {

	static {
		WritingXmlValidator.writeXml = false;
	}

	private ConfigurablePasswordPolicy policy = new ConfigurablePasswordPolicy();

	@Before
	public void configurePolicy() {
		policy.configure(null);
	}

	@Test
	@Transactional
	public void testChangePassword() throws Exception {
		LoginData loginData = login();

		loginData.setOldpassword("test");
		loginData.setPassword("Test123!!");
		loginData.setPasswordConfirmation("Test123!!");

		Mockito.when(site.getPasswordPolicy()).thenReturn(policy);

		CallableAction changePassword = getAction("form-auth", "changePassword")
				.withParam("form_action", "changePassword").withParam("action", "changePassword")
				.withParam("username", "subject-3").getCallableAction(loginData);
		changePassword.perform();
		validate(changePassword.getAction());
	}

	@Test
	@Transactional
	public void testChangePasswordWrongOld() throws Exception {
		LoginData loginData = login();

		loginData.setOldpassword("wrong");
		loginData.setPassword("Test123!!");
		loginData.setPasswordConfirmation("Test123!!");

		Mockito.when(site.getPasswordPolicy()).thenReturn(policy);

		CallableAction changePassword = getAction("form-auth", "changePassword")
				.withParam("form_action", "changePassword").withParam("action", "changePassword")
				.withParam("username", "subject-3").getCallableAction(loginData);
		changePassword.perform();
		validate(changePassword.getAction());
	}

	@Test
	@Transactional
	public void testChangePasswordNoMatch() throws Exception {
		LoginData loginData = login();

		loginData.setOldpassword("test");
		loginData.setPassword("Test123!!");
		loginData.setPasswordConfirmation("Test123$$");

		Mockito.when(site.getPasswordPolicy()).thenReturn(policy);

		CallableAction changePassword = getAction("form-auth", "changePassword")
				.withParam("form_action", "changePassword").withParam("action", "changePassword")
				.withParam("username", "subject-3").getCallableAction(loginData);
		changePassword.perform();
		validate(changePassword.getAction());
	}

	@Test
	@Transactional
	public void testChangePasswordVoilatePolicy() throws Exception {
		LoginData loginData = login();

		loginData.setOldpassword("test");
		loginData.setPassword("§ß ");
		loginData.setPasswordConfirmation("§ß ");
		
		
		ConfigurablePasswordPolicy newPolicy = new ConfigurablePasswordPolicy();
		List<Property> properties = new ArrayList<>();
		SimpleProperty configurablePasswordPolicy = new SimpleProperty(
				PropertySupport.PREFIX_PLATFORM + "configurablePasswordPolicy", null);
		configurablePasswordPolicy.setClob("numCharacterGroups=3");
		properties.add(configurablePasswordPolicy);
		PropertyHolder platformProperties = new PropertyHolder(PropertySupport.PREFIX_PLATFORM, properties);
		newPolicy.configure(platformProperties);
		

		Mockito.when(site.getPasswordPolicy()).thenReturn(newPolicy);

		CallableAction changePassword = getAction("form-auth", "changePassword")
				.withParam("form_action", "changePassword").withParam("action", "changePassword")
				.withParam("username", "subject-3").getCallableAction(loginData);
		changePassword.perform();
		validate(changePassword.getAction());
	}

	private LoginData login() throws ProcessingException {
		new AuthenticationTestDataProvider().writeTestData(em);

		LoginData loginData = new LoginData();
		loginData.setUsername("subject-3");
		loginData.setPassword("test");
		getLoginAction(loginData).perform();

		return loginData;
	}

}
