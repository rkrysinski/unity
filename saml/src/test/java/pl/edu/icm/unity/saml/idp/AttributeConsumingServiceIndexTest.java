package pl.edu.icm.unity.saml.idp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

import org.junit.jupiter.api.Test;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.messages.XMLExpandedMessage;
import eu.unicore.samly2.proto.AuthnRequest;
import eu.unicore.samly2.trust.EnumeratedTrustChecker;
import eu.unicore.samly2.validators.ReplayAttackChecker;
import pl.edu.icm.unity.saml.validator.WebAuthRequestValidator;
import eu.unicore.samly2.exceptions.SAMLResponderException;

/**
 * Tests handling of AttributeConsumingServiceIndex in AuthnRequest.
 */
public class AttributeConsumingServiceIndexTest
{
	@Test
	public void shouldIgnoreAttributeConsumingServiceIndexWhenConfigured()
	{
	AuthnRequest request = new AuthnRequest(new NameID("https://unity-sp.example", SAMLConstants.NFORMAT_ENTITY).getXBean());
	request.getXMLBean().setAttributeConsumingServiceIndex(1);
	EnumeratedTrustChecker checker = new EnumeratedTrustChecker();
	checker.addTrustedIssuer("https://unity-sp.example", "https://unity-sp.example/return");
	WebAuthRequestValidator validator = new WebAuthRequestValidator(
		"https://unity-idp.example",
		checker,
		Duration.of(1000L, ChronoUnit.MILLIS),
		new ReplayAttackChecker(),
		true);
	validator.addKnownRequester("https://unity-sp.example");
	XMLExpandedMessage verifiable = new XMLExpandedMessage(request.getXMLBeanDoc(), request.getXMLBeanDoc().getAuthnRequest());
	Throwable error = catchThrowable(() -> validator.validate(request.getXMLBeanDoc(), verifiable));
	assertThat(error).isNull();
	}

	@Test
	public void shouldRejectAttributeConsumingServiceIndexWhenNotIgnored()
	{
	AuthnRequest request = new AuthnRequest(new NameID("https://unity-sp.example", SAMLConstants.NFORMAT_ENTITY).getXBean());
	request.getXMLBean().setAttributeConsumingServiceIndex(1);
	EnumeratedTrustChecker checker = new EnumeratedTrustChecker();
	checker.addTrustedIssuer("https://unity-sp.example", "https://unity-sp.example/return");
	WebAuthRequestValidator validator = new WebAuthRequestValidator(
		"https://unity-idp.example",
		checker,
		Duration.of(1000L, ChronoUnit.MILLIS),
		new ReplayAttackChecker(),
		false);
	validator.addKnownRequester("https://unity-sp.example");
	XMLExpandedMessage verifiable = new XMLExpandedMessage(request.getXMLBeanDoc(), request.getXMLBeanDoc().getAuthnRequest());
	Throwable error = catchThrowable(() -> validator.validate(request.getXMLBeanDoc(), verifiable));
	assertThat(error).isInstanceOf(SAMLResponderException.class);
	}
}
