package pl.edu.icm.unity.saml.idp;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.Test;

import eu.unicore.samly2.SAMLConstants;
import eu.unicore.samly2.elements.NameID;
import eu.unicore.samly2.exceptions.SAMLResponderException;
import eu.unicore.samly2.messages.XMLExpandedMessage;
import eu.unicore.samly2.proto.AuthnRequest;
import eu.unicore.samly2.trust.EnumeratedTrustChecker;
import eu.unicore.samly2.validators.ReplayAttackChecker;
import pl.edu.icm.unity.saml.validator.WebAuthRequestValidator;

/**
 * Tests handling of AttributeConsumingServiceIndex in AuthnRequest.
 */
public class AttributeConsumingServiceIndexTest
{
private static final String SP_ENTITY_ID = "https://unity-sp.example";
private static final String SP_RETURN_URL = "https://unity-sp.example/return";
private static final String IDP_ENDPOINT_URI = "https://unity-idp.example";

@Test
public void shouldIgnoreAttributeConsumingServiceIndexWhenConfigured()
{
AuthnRequest request = new AuthnRequest(new NameID(SP_ENTITY_ID, SAMLConstants.NFORMAT_ENTITY).getXBean());
request.getXMLBean().setAttributeConsumingServiceIndex(1);
EnumeratedTrustChecker checker = new EnumeratedTrustChecker();
checker.addTrustedIssuer(SP_ENTITY_ID, SP_RETURN_URL);
WebAuthRequestValidator validator = new WebAuthRequestValidator(
IDP_ENDPOINT_URI,
checker,
Duration.ofSeconds(5),
new ReplayAttackChecker(),
true);
validator.addKnownRequester(SP_ENTITY_ID);
XMLExpandedMessage verifiable = new XMLExpandedMessage(request.getXMLBeanDoc(), request.getXMLBeanDoc().getAuthnRequest());
assertThatCode(() -> validator.validate(request.getXMLBeanDoc(), verifiable)).doesNotThrowAnyException();
}

@Test
public void shouldRejectAttributeConsumingServiceIndexWhenNotIgnored()
{
AuthnRequest request = new AuthnRequest(new NameID(SP_ENTITY_ID, SAMLConstants.NFORMAT_ENTITY).getXBean());
request.getXMLBean().setAttributeConsumingServiceIndex(1);
EnumeratedTrustChecker checker = new EnumeratedTrustChecker();
checker.addTrustedIssuer(SP_ENTITY_ID, SP_RETURN_URL);
WebAuthRequestValidator validator = new WebAuthRequestValidator(
IDP_ENDPOINT_URI,
checker,
Duration.ofSeconds(5),
new ReplayAttackChecker(),
false);
validator.addKnownRequester(SP_ENTITY_ID);
XMLExpandedMessage verifiable = new XMLExpandedMessage(request.getXMLBeanDoc(), request.getXMLBeanDoc().getAuthnRequest());
assertThatThrownBy(() -> validator.validate(request.getXMLBeanDoc(), verifiable))
.isInstanceOf(SAMLResponderException.class)
.hasMessageContaining("AttributeConsumingServiceIndex");
}

@Test
public void shouldRespectFlagWhenAcsUrlIsPresent()
{
AuthnRequest request = new AuthnRequest(new NameID(SP_ENTITY_ID, SAMLConstants.NFORMAT_ENTITY).getXBean());
request.getXMLBean().setAttributeConsumingServiceIndex(1);
request.getXMLBean().setAssertionConsumerServiceURL(SP_RETURN_URL);

EnumeratedTrustChecker checker = new EnumeratedTrustChecker();
checker.addTrustedIssuer(SP_ENTITY_ID, SP_RETURN_URL);

var okValidator = new WebAuthRequestValidator(
IDP_ENDPOINT_URI, checker, Duration.ofSeconds(5), new ReplayAttackChecker(), true);
var verifiable = new XMLExpandedMessage(request.getXMLBeanDoc(), request.getXMLBeanDoc().getAuthnRequest());
assertThatCode(() -> okValidator.validate(request.getXMLBeanDoc(), verifiable)).doesNotThrowAnyException();

var badValidator = new WebAuthRequestValidator(
IDP_ENDPOINT_URI, checker, Duration.ofSeconds(5), new ReplayAttackChecker(), false);
assertThatThrownBy(() -> badValidator.validate(request.getXMLBeanDoc(), verifiable))
.isInstanceOf(SAMLResponderException.class)
.hasMessageContaining("AttributeConsumingServiceIndex");
}
}

