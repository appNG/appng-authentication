<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:ait="http://aiticon.de"
	xmlns:xs="http://www.w3.org/2001/XMLSchema" exclude-result-prefixes="ait xs">
	<xsl:output method="xhtml" />
	
	<!-- body -->
	<xsl:template match="content" mode="html-body" priority="10">
		<xsl:param name="subject" tunnel="yes" />

		<body>
			<div id="login_container">
				<div id="positioner">
					<div id="content">
						<div id="content_head">
							<xsl:if test=".//selection[@id = 'lang']">
								<form class="form-language-selector" name="form_lang" method="get">
									<xsl:if test=".//get-param[@name = 'action'] != ''">
										<input type="hidden" name="action">
											<xsl:attribute name="value" select=".//get-param[@name = 'action']"/>
										</input>
									</xsl:if>
									<select id="lang_select" name="lang">
										<xsl:attribute name="onChange" select="'return app.submitForm(''form_lang'')'"/>
										<xsl:for-each select=".//selection[@id = 'lang']/option">
											<option>
												<xsl:attribute name="value" select="@value"/>
												<xsl:if test="@selected = 'true'">
													<xsl:attribute name="selected" select="'selected'"/>
												</xsl:if>
												<xsl:value-of select="@value"/>
											</option>
										</xsl:for-each>
									</select>
									<div id="lang_skin">
										<span>
											<xsl:for-each select=".//selection[@id = 'lang']/option">
												<xsl:if test="@selected = 'true'">
													<xsl:value-of select="@value"/>
												</xsl:if>
											</xsl:for-each>
										</span>
										<a href="javascript:void(0)" id="lang_skin_button">&#160;</a>
									</div>
									<ul id="lang_skin_list">
										<xsl:for-each select=".//selection[@id = 'lang']/option">
											<li>
												<a>
													<xsl:attribute name="id" select="@value"/>
													<xsl:attribute name="href" select="'javascript:void(0)'"/>
													<xsl:if test="@selected = 'true'">
														<xsl:attribute name="class" select="'selected'"/>
													</xsl:if>
													<xsl:value-of select="@value"/>
												</a>
											</li>
										</xsl:for-each>
									</ul>
								</form>
								<script language="javascript" type="text/javascript">
									$('#lang_select').css('display', 'none');
									$('#lang_skin span').html($("#lang_select option:selected").html());
									$('#lang_skin').css('display', 'block');
									
									$('#lang_skin_button').click(function(){
									$('#lang_skin_list').toggle(400);
									}).focus(function(){
									$(this).blur();
									});
									$('#lang_skin_list li a').click(function(){
									$('#lang_skin span').html($(this).html());
									$("#lang_select option:selected").removeAttr('selected');
									$("#lang_select option[value='" + $(this).attr('id') + "']").attr('selected', 'selected');
									$('#lang_select').change();
									$('#lang_skin_list').toggle(400);
									}).focus(function(){
									$(this).blur();
									});
								</script>
							</xsl:if>
						</div>
						<div id="logo">
							<img src="/template/assets/logo_trans.png" border="0" alt="" title="" width="220" height="110" />
						</div>

						<xsl:apply-templates select="//page/structure/section/element/action" mode="custom" />
						
						<xsl:apply-templates select="//messages"/>

						<div class="hr"></div>
					</div>
				</div>
			</div>

		</body>
	</xsl:template>
</xsl:stylesheet>
