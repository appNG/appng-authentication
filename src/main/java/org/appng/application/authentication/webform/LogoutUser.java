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

import java.util.Locale;

import org.apache.commons.lang3.StringUtils;
import org.appng.api.ActionProvider;
import org.appng.api.Environment;
import org.appng.api.FieldProcessor;
import org.appng.api.Options;
import org.appng.api.Request;
import org.appng.api.model.Application;
import org.appng.api.model.Site;
import org.appng.application.authentication.AbstractLogon;
import org.appng.application.authentication.MessageConstants;
import org.slf4j.Logger;
import org.springframework.http.HttpStatus;

import lombok.extern.slf4j.Slf4j;

/**
 * @author Matthias Herlitzius
 * @author Matthias Müller
 */
@Slf4j
public class LogoutUser extends AbstractLogon implements ActionProvider<LoginData> {

	public void perform(Site site, Application application, Environment environment, Options options, Request request,
			LoginData valueHolder, FieldProcessor fp) {
		if (environment.isSubjectAuthenticated()) {
			Locale locale = environment.getLocale();
			getCoreService(application).logoutSubject(environment);
			String message = application.getMessage(locale, MessageConstants.LOGOUT_SUCCESSFUL);
			fp.addOkMessage(message);
		}
		String forward = request.getParameter("forward");
		if (StringUtils.isBlank(forward)) {
			LOGGER.info("request parameter 'forward' not set, using option {}", options.getOption("forward"));
			forward = options.getOptionValue("forward", "forward");
		}
		if (StringUtils.isNotBlank(forward)) {
			LOGGER.info("forwarding to {}", forward);
			site.sendRedirect(environment, forward, HttpStatus.FOUND.value());
		}
	}

	protected Logger log() {
		return LOGGER;
	}

}
