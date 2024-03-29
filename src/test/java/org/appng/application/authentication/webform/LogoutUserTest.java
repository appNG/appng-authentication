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

import org.appng.api.model.Subject;
import org.appng.api.support.environment.DefaultEnvironment;
import org.appng.application.authentication.BaseLoginTest;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;

public class LogoutUserTest extends BaseLoginTest {

	@Test
	public void testLogoutOk() throws Exception {
		Subject mock = Mockito.mock(Subject.class);
		Mockito.when(mock.isAuthenticated()).thenReturn(true);
		((DefaultEnvironment) environment).setSubject(mock);
		Assert.assertEquals(mock, environment.getSubject());
		getAction("form-auth", "logout").withParam("action", "logout").withParam("forward", "foo/bar").getCallableAction(null).perform();
		Assert.assertNull(environment.getSubject());
		Mockito.verify(site).sendRedirect(environment, "foo/bar", HttpStatus.FOUND.value());
	}

}
