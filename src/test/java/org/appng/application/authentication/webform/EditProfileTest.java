/*
 * Copyright 2011-2019 the original author or authors.
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

import org.appng.api.support.CallableAction;
import org.appng.application.authentication.BaseLoginTest;
import org.appng.core.domain.SubjectImpl;
import org.appng.testsupport.validation.WritingXmlValidator;
import org.appng.testsupport.validation.XPathDifferenceHandler;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.springframework.transaction.annotation.Transactional;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EditProfileTest extends BaseLoginTest {

	static {
		WritingXmlValidator.writeXml = false;
	}

	@Test
	@Transactional
	public void testEditProfile() throws Exception {
		new AuthenticationTestDataProvider().writeTestData(em);

		LoginData loginData = new LoginData();
		loginData.setUsername("subject-3");
		loginData.setPassword("test");
		getLoginAction(loginData).perform();

		SubjectImpl subject = new SubjectImpl();
		subject.setRealname("John Doe");
		subject.setLanguage("de");
		subject.setTimeZone("Europe/Rome");
		subject.setEmail("john@doe.org");
		CallableAction editProfile = getAction("profileEvent", "editProfile").withParam("form_action", "editProfile")
				.getCallableAction(subject);
		editProfile.perform();
		XPathDifferenceHandler differenceListener = new XPathDifferenceHandler(true);
		// lastLogin
		differenceListener.ignoreDifference("/action/data/result/field/value/text()");
		// options for timezone
		differenceListener.ignoreDifference("/action/data/selection/optionGroup");
		differenceListener.ignoreDifference("/action/data/selection/optionGroup/option");
		validate(editProfile.getAction(), differenceListener);
	}

}
