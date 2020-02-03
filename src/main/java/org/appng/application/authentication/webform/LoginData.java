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

import javax.validation.constraints.NotNull;

import lombok.Setter;

@Setter
public class LoginData {

	private String username;
	private String oldpassword;
	private String password;
	private String passwordConfirmation;
	private String digest;

	public String getUsername() {
		return username;
	}

	@NotNull(groups = PasswordChange.class, message = "{password.oldRequired}")
	public String getOldpassword() {
		return oldpassword;
	}

	@NotNull(groups = PasswordChange.class, message = "{password.newRequired}")
	public String getPassword() {
		return password;
	}

	@NotNull(groups = PasswordChange.class, message = "{password.confirmRequired}")
	public String getPasswordConfirmation() {
		return passwordConfirmation;
	}

	public String getDigest() {
		return digest;
	}

}
