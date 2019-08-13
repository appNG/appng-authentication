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
package org.appng.application.authentication.digest;

import org.apache.commons.lang3.StringUtils;
import org.appng.api.Environment;
import org.appng.api.FieldProcessor;
import org.appng.api.Options;
import org.appng.api.Request;
import org.appng.api.SiteProperties;
import org.appng.api.model.Application;
import org.appng.api.model.Site;
import org.appng.api.support.environment.DefaultEnvironment;
import org.appng.application.authentication.AbstractLogon;
import org.appng.application.authentication.AuthenticationSettings;
import org.appng.application.authentication.webform.LoginData;
import org.appng.core.security.DigestUtil;
import org.appng.core.security.DigestValidator;
import org.appng.core.service.CoreService;
import org.slf4j.Logger;
import org.springframework.http.HttpStatus;

import lombok.extern.slf4j.Slf4j;

/**
 * A login method that takes the request parameter "digest" and tries to authenticate the user by the given value.
 * 
 * @author Matthias Herlitzius
 * @author Matthias Müller
 * @see DigestUtil
 * @see DigestValidator
 * @see CoreService#login(Environment, String, int)
 */
@Slf4j
public class DigestLogin extends AbstractLogon {

	public void perform(Site site, Application application, Environment environment, Options options, Request request,
			LoginData loginData, FieldProcessor fp) {
		String digest = request.getParameter("digest");
		if (StringUtils.isNotBlank(digest)) {
			Integer digestMaxValidity = application.getProperties()
					.getInteger(AuthenticationSettings.DIGEST_MAX_VALIDITY);
			DigestValidator validator = new DigestValidator(digest, digestMaxValidity);
			String username = validator.getUsername();
			LOGGER.debug("received login digest for user {}", username);
			boolean success = false;
			if (environment.isSubjectAuthenticated()) {
				String currentUser = environment.getSubject().getAuthName();
				if (StringUtils.isNotBlank(username) && !currentUser.equals(username)) {
					LOGGER.debug("a different user ({}) is logged in, performing log-out first.", currentUser);
					getCoreService(application).logoutSubject(environment);
				}
			}
			if (!environment.isSubjectAuthenticated()) {
				success = getCoreService(application).login(environment, digest, digestMaxValidity);
				LOGGER.debug("digest login for user {} " + (success ? "succeeded" : "failed") + ".", username);
			} else {
				LOGGER.debug("user {} is already logged in", environment.getSubject().getAuthName());
			}
			String target = request.getParameter("forward");
			String managerPath = site.getProperties().getString(SiteProperties.MANAGER_PATH);
			if (StringUtils.isNotBlank(target)) {
				target = target.substring(managerPath.length());
			} else if (application.getProperties()
					.getBoolean(AuthenticationSettings.DIGEST_LOGIN_REDIRECT_WITH_SERVLET_PATH)) {
				target = ((DefaultEnvironment) environment).getServletRequest().getServletPath();
				target = target.substring(managerPath.length());
			} else {
				target = application.getProperties().getString(AuthenticationSettings.SUCCESS_PAGE);
			}
			processLogonResult(site, application, environment, options, fp, success, target, HttpStatus.FOUND, true);
		}
	}

	@Override
	protected Logger log() {
		return LOGGER;
	}

}
