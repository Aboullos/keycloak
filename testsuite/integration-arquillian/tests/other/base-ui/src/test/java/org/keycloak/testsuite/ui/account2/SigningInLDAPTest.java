/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.ui.account2;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.keycloak.authentication.authenticators.browser.WebAuthnAuthenticatorFactory;
import org.keycloak.authentication.authenticators.browser.WebAuthnPasswordlessAuthenticatorFactory;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.authentication.requiredactions.WebAuthnRegisterFactory;
import org.keycloak.common.Profile;
import org.keycloak.models.RealmModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.models.utils.Base32;
import org.keycloak.models.utils.TimeBasedOTP;
import org.keycloak.representations.idm.*;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.testsuite.WebAuthnAssume;
import org.keycloak.testsuite.admin.Users;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.auth.page.login.OTPSetup;
import org.keycloak.testsuite.auth.page.login.UpdatePassword;
import org.keycloak.testsuite.federation.ldap.AbstractLDAPTest;
import org.keycloak.testsuite.federation.ldap.LDAPTestContext;
import org.keycloak.testsuite.pages.webauthn.WebAuthnRegisterPage;
import org.keycloak.testsuite.ui.account2.page.AbstractLoggedInPage;
import org.keycloak.testsuite.ui.account2.page.SigningInPage;
import org.keycloak.testsuite.util.LDAPTestUtils;

import static org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED;
import static org.keycloak.representations.idm.CredentialRepresentation.PASSWORD;
import static org.keycloak.testsuite.admin.Users.setPasswordFor;
import static org.keycloak.testsuite.auth.page.AuthRealm.TEST;

/**
 * @author Vaclav Muzikar <vmuzikar@redhat.com>
 */
@EnableFeature(value = Profile.Feature.ACCOUNT2, skipRestart = true)
@EnableFeature(value = Profile.Feature.ACCOUNT_API, skipRestart = true)
@EnableFeature(value = Profile.Feature.WEB_AUTHN, skipRestart = true, onlyForProduct = true)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SigningInLDAPTest extends BaseAccountPageTest {
    public static final String WEBAUTHN_FLOW_ID = "75e2390e-f296-49e6-acf8-6d21071d7e10";

    @Page
    private SigningInPage signingInPage;

    @Page
    private UpdatePassword updatePasswordPage;

    @Page
    private OTPSetup otpSetupPage;

    @Page
    private WebAuthnRegisterPage webAuthnRegisterPage;

    private SigningInPage.CredentialType passwordCredentialType;
    private SigningInPage.CredentialType otpCredentialType;
    private SigningInPage.CredentialType webAuthnCredentialType;
    private SigningInPage.CredentialType webAuthnPwdlessCredentialType;
    private TimeBasedOTP otpGenerator;

    @Override
    protected AbstractLoggedInPage getAccountPage() {
        return signingInPage;
    }

    @Override
    protected void afterAbstractKeycloakTestRealmImport() {
        super.afterAbstractKeycloakTestRealmImport();

        // configure WebAuthn
        // we can't do this during the realm import because we'd need to specify all built-in flows as well

        AuthenticationFlowRepresentation flow = new AuthenticationFlowRepresentation();
        flow.setId(WEBAUTHN_FLOW_ID);
        flow.setAlias("webauthn flow");
        flow.setProviderId("basic-flow");
        flow.setBuiltIn(false);
        flow.setTopLevel(true);
        testRealmResource().flows().createFlow(flow);

        AuthenticationExecutionRepresentation execution = new AuthenticationExecutionRepresentation();
        execution.setAuthenticator(WebAuthnAuthenticatorFactory.PROVIDER_ID);
        execution.setPriority(10);
        execution.setRequirement(REQUIRED.toString());
        execution.setParentFlow(WEBAUTHN_FLOW_ID);
        testRealmResource().flows().addExecution(execution);

        execution.setAuthenticator(WebAuthnPasswordlessAuthenticatorFactory.PROVIDER_ID);
        testRealmResource().flows().addExecution(execution);

        RequiredActionProviderSimpleRepresentation requiredAction = new RequiredActionProviderSimpleRepresentation();
        requiredAction.setProviderId(WebAuthnRegisterFactory.PROVIDER_ID);
        requiredAction.setName("blahblah");
        testRealmResource().flows().registerRequiredAction(requiredAction);

        requiredAction.setProviderId(WebAuthnPasswordlessRegisterFactory.PROVIDER_ID);
        testRealmResource().flows().registerRequiredAction(requiredAction);

        // no need to actually configure the authentication, in Account Console tests we just verify the registration
    }

    @Override
    public void setDefaultPageUriParameters() {
        super.setDefaultPageUriParameters();
        updatePasswordPage.setAuthRealm(TEST);
        otpSetupPage.setAuthRealm(TEST);
    }

    @Before
    public void beforeSigningInTest() {
        passwordCredentialType = signingInPage.getCredentialType(PasswordCredentialModel.TYPE);
        otpCredentialType = signingInPage.getCredentialType(OTPCredentialModel.TYPE);
        webAuthnCredentialType = signingInPage.getCredentialType(WebAuthnCredentialModel.TYPE_TWOFACTOR);
        webAuthnPwdlessCredentialType = signingInPage.getCredentialType(WebAuthnCredentialModel.TYPE_PASSWORDLESS);

        RealmRepresentation realm = testRealmResource().toRepresentation();
        otpGenerator = new TimeBasedOTP(realm.getOtpPolicyAlgorithm(), realm.getOtpPolicyDigits(), realm.getOtpPolicyPeriod(), 0);
    }

    @Override
    public void beforeAuthTest() {
        String userName = "johnkeycloak";
        String firstName = "Jonh";
        String lastName = "Doe";
        String email = "john@email.org";

        testingClient.server().run(session -> {
            LDAPTestContext ctx = LDAPTestContext.init(session);
            RealmModel appRealm = ctx.getRealm();

            // Delete all LDAP users and add some new for testing
            LDAPTestUtils.removeAllLDAPUsers(ctx.getLdapProvider(), appRealm);

            LDAPObject john = LDAPTestUtils.addLDAPUser(ctx.getLdapProvider(), appRealm, userName, firstName, lastName, email, null, "1234");
            LDAPTestUtils.updateLDAPPassword(ctx.getLdapProvider(), john, PASSWORD);
        });

        testRealmLoginPage.setAuthRealm(testRealmPage);
        testRealmAccountPage.setAuthRealm(testRealmPage);

        testUser = createUserRepresentation(userName, email, firstName, lastName, true);
        setPasswordFor(testUser, PASSWORD);

        resetTestRealmSession();
    }

    @Test
    public void createdNotVisibleTest() {
        // Test
    }
}
