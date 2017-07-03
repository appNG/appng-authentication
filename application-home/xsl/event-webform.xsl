<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ait="http://aiticon.de" xmlns:xs="http://www.w3.org/2001/XMLSchema" exclude-result-prefixes="ait xs">
	<xsl:output method="xhtml"/>
	
	<!-- action login -->
	<xsl:template match="action[@id='login' or @id='logout' or @id='resetPassword']" mode="custom" priority="10">
		<xsl:variable name="action-id" select="@id"/>
		<xsl:variable name="event-id" select="@eventId"/>
		<xsl:variable name="event-data" select="bean [@ref='loginUser']"/>
		
		<!-- formular data taken from event/data -->
		<form action="" name="form_{$event-id}_{$action-id}" enctype="multipart/form-data" method="post" class="without-submit-control" onsubmit="return true">
			<input type="hidden" name="form_action" value="loginUser"/>

			<div class="label"> 
				<label for="user"> 
					<xsl:value-of select="appng:search-label('username',.)"/> 
				</label> 
			</div>
			<div class="field">
				<input type="text" id="user" name="username" value="" class="text">
				<xsl:if test="../messages[@ref='login']/message[@ref='login' and @class='ERROR']">
					<xsl:attribute name="class">text error</xsl:attribute>
				</xsl:if>
				</input>
				<script type="text/javascript"> jQuery('#user').get(0).focus()</script>
			</div>
			<div class="label"> 
				<label for="pass"> 
					<xsl:value-of select="appng:search-label('password',.)"/> 
				</label> 
			</div>
			<div class="field">
				<input type="password" id="pass" name="password" value="" class="text">
				<xsl:if test="../messages[@ref='login']/message[@ref='login' and @class='ERROR']">
					<xsl:attribute name="class">text error</xsl:attribute>
				</xsl:if>
				</input>
			</div>
			<xsl:call-template name="add-csrf-token"/>
			
			<div class="buttons_panel">
				<div class="center">
					<a href="javascript:void(0)" class="btn_login" onclick="return app.submitForm('form_{$event-id}_{$action-id}')"><xsl:value-of select="appng:search-label('logon',.)"/></a>
					<input type="image" onclick="return app.submitForm('form_{$event-id}_{$action-id}')" style="display:none;"/>
				</div>
			</div>
			<input type="submit" name="submit-button" value="submit" class="submit-button"/>
		</form>
		<p class="clr">&#160;</p>
		
		<div class="buttons_panel">
			<div class="center">
				<xsl:if test="$event-id = 'form-ntlm'"><a href="{$reload-url}?tl={current-time()}" class="btn_reload"><xsl:value-of select="appng:search-label('logon.again',.)"/></a></xsl:if>
				<a href="?action=forgotPassword" class="btn_reset"><xsl:value-of select="appng:search-label('forgot.password',.)"/></a>
			</div>
		</div>
	</xsl:template>
	
	<!-- digest action login -->
	<!--<xsl:template match="events/event[@id eq 'form-digest']/action[@id='digest-login']" mode="custom" priority="10">
	</xsl:template>
	-->

	<!-- forgotpw -->
	<xsl:template match="action[@id='forgotPassword']" mode="custom" priority="10">
		<xsl:variable name="action-id" select="@id"/>
		<xsl:variable name="event-id" select="@eventId"/>
		<xsl:variable name="event-data" select="bean [@ref='forgotPassword']"/>
		
		<form action="" name="form_{$event-id}_{$action-id}" enctype="multipart/form-data" method="post">
			<input type="hidden" name="form_action" value="forgotPassword"/>
			<input type="hidden" name="action" value="forgotPassword"/>
			<div class="label"> 
				<label for="user"> 
					<xsl:value-of select="appng:search-label('username',.)"/> 
				</label> 
			</div>
			<div class="field">
				<input type="text" id="user" name="username" value="" class="text" />
			</div>
			<div class="buttons_panel">
				<div class="center">
					<a class="btn_back" href="{$current-url}" ><xsl:value-of select="appng:search-label('back',.)"/></a>
					<a href="javascript:void(0)" class="btn_login" onclick="return app.submitForm('form_{$event-id}_{$action-id}')"><xsl:value-of select="appng:search-label('submit',.)"/></a>
				</div>
			</div>
		</form>
		<p class="clr">&#160;</p>
	</xsl:template>
	
	<!-- action change password -->
	<xsl:template match="action[@id='changePassword']" mode="custom" priority="10">
		<xsl:param name="action-id" select="generate-id(.)"/>
		<xsl:param name="action-action" select="@id"/>
		<xsl:param name="title">
			<xsl:apply-templates select="config/title"/>
		</xsl:param>
		
		<xsl:param name="action-validation">
			<xsl:choose>
				<xsl:when test="@clientValidation"><xsl:value-of select="@clientValidation"/></xsl:when>
				<xsl:otherwise>false</xsl:otherwise>
			</xsl:choose>
		</xsl:param>
		
		<!-- formular data taken from data -->
		<form action="" name="form_{$action-id}" enctype="multipart/form-data" method="post" class="without-submit-control" onsubmit="return true">
			
			<input type="hidden" name="form_action" value="changePassword"/>
			<input type="hidden" name="action" value="changePassword"/>
			
			<xsl:apply-templates select="config/meta-data/field" mode="form">
				<xsl:with-param name="action-id" select="$action-id" tunnel="yes"/>
				<xsl:with-param name="action-data" select="data" tunnel="yes"/>
				<xsl:with-param name="action-userdata" select="userdata" tunnel="yes"/>
				<xsl:with-param name="action-validation" select="$action-validation" tunnel="yes"/>
			</xsl:apply-templates>
			
			<div class="buttons_panel">
				<div class="center">
					<a class="btn_back" href="{$base-url}" ><xsl:value-of select="appng:search-label('back',.)"/></a>
					<a href="javascript:void(0)" class="btn_login" onclick="return app.submitForm('form_{$action-id}')"><xsl:value-of select="appng:search-label('submit',.)"/></a>
					<input type="image" onclick="return app.submitForm('form_{$action-id}')" style="display:none;"/>
				</div>
			</div>
			<input type="submit" name="submit-button" value="submit" class="submit-button"/>
		</form>
		<p class="clr">&#160;</p>
	</xsl:template>

</xsl:stylesheet>