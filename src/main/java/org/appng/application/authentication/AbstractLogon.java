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
package org.appng.application.authentication;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.appng.api.ActionProvider;
import org.appng.api.Environment;
import org.appng.api.FieldProcessor;
import org.appng.api.Options;
import org.appng.api.Scope;
import org.appng.api.model.Application;
import org.appng.api.model.Group;
import org.appng.api.model.Site;
import org.appng.api.support.environment.EnvironmentKeys;
import org.appng.application.authentication.webform.LoginData;
import org.appng.core.service.CoreService;
import org.slf4j.Logger;
import org.springframework.http.HttpStatus;

public abstract class AbstractLogon implements ActionProvider<LoginData> {

	public static final String PRE_LOGIN_PATH = "preLoginPath";

	protected static final String PARAM_ACTION = "action";
	protected static final String PARAM_FORM_ACTION = "form_action";
	protected static final String PARAM_PASSWORD = "password";
	protected static final String PARAM_HASH = "hash";
	protected static final String PARAM_USERNAME = "username";

	protected static final String ACTION_FORGOT_PASSWORD = "forgotPassword";
	protected static final String ACTION_RESET_PASSWORD = "resetPassword";
	protected static final String ACTION_LOGIN = "login";
	protected CoreService coreService;

	protected AbstractLogon(CoreService coreService) {
		this.coreService = coreService;
	}

	protected void processLogonResult(Site site, Application application, Environment env, Options options,
			FieldProcessor fp, boolean success, String successPage) {
		HttpStatus status = HttpStatus
				.valueOf(application.getProperties().getInteger(AuthenticationSettings.LOGIN_FORWARD_STATUS));
		processLogonResult(site, application, env, options, fp, success, successPage, status, true);
	}

	protected void processLogonResult(Site site, Application application, Environment env, Options options,
			FieldProcessor fp, boolean success, String successPage, HttpStatus status, boolean doRedirect) {
		String executePath = env.getAttributeAsString(Scope.REQUEST, EnvironmentKeys.EXECUTE_PATH);
		String defaultPath = env.getAttributeAsString(Scope.REQUEST, EnvironmentKeys.DEFAULT_PATH);

		if (StringUtils.isBlank(executePath)) {
			executePath = defaultPath;
		}

		if (success) {
			String message = application.getMessage(env.getLocale(), MessageConstants.USER_AUTHENTICATED);
			fp.addOkMessage(message);
			if (doRedirect) {
				String baseUrl = env.getAttributeAsString(Scope.REQUEST, EnvironmentKeys.BASE_URL);
				String originalServletPath = env.getAttributeAsString(Scope.REQUEST, EnvironmentKeys.SERVLETPATH);
				boolean enableDeeplinks = application.getProperties()
						.getBoolean(AuthenticationSettings.ENABLE_DEEPLINKS, Boolean.TRUE);

				String targetPage = null;
				if (enableDeeplinks && (!executePath.startsWith(originalServletPath))
						&& (!originalServletPath.startsWith(executePath))) {
					targetPage = env.removeAttribute(Scope.SESSION, PRE_LOGIN_PATH);
					log().debug("{} is enabled, using session attribute {} as target: {}",
							AuthenticationSettings.ENABLE_DEEPLINKS, PRE_LOGIN_PATH, targetPage);
				}
				if (null == targetPage) {
					targetPage = baseUrl + successPage;
					log().debug("target is empty, using {}", targetPage);
				}

				log().debug("redirecting to {} with status {}", targetPage, status);
				site.sendRedirect(env, targetPage, status.value());
			} else {
				log().debug("no redirect required");
			}
		} else {
			String messageKey;
			if (Boolean.TRUE.equals(env.removeAttribute(Scope.REQUEST, "subject.locked"))) {
				messageKey = MessageConstants.USER_IS_LOCKED;
			} else if (Boolean.TRUE.equals(env.removeAttribute(Scope.REQUEST, "subject.mustRecoverPassword"))) {
				messageKey = MessageConstants.PASSWORD_RECOVERY_NEEDED;
			} else {
				messageKey = MessageConstants.AUTHENTICATION_ERROR;
			}
			fp.addErrorMessage(application.getMessage(env.getLocale(), messageKey));
		}
	}

	protected void processLogonResult(Site site, Application application, Environment env, Options options,
			FieldProcessor fp, boolean success) {
		String successPage = application.getProperties().getString(AuthenticationSettings.SUCCESS_PAGE);

		String successPageGroupwise = application.getProperties()
				.getClob(AuthenticationSettings.SUCCESS_PAGE_GROUPWISE);
		if (success && StringUtils.isNotBlank(successPageGroupwise)) {
			List<String> groupNames = env.getSubject().getGroups().stream().map(Group::getName)
					.collect(Collectors.toList());
			String[] successPagesForGroup = successPageGroupwise.split(StringUtils.LF);
			for (String target : successPagesForGroup) {
				target = StringUtils.trim(target);
				if (!target.startsWith("#")) {
					String[] pair = target.split("=");
					String groupName = StringUtils.trim(pair[0]);
					if (groupNames.contains(groupName)) {
						successPage = StringUtils.trim(pair[1]);
						log().debug("Found matching target {} for group {}: {}", successPage, groupName, successPage);
						break;
					}
				}
			}
		}

		processLogonResult(site, application, env, options, fp, success, successPage);
	}

	public boolean isSubjectLoggedIn(Environment env) {
		return env.isSubjectAuthenticated();
	}

	protected abstract Logger log();
}
