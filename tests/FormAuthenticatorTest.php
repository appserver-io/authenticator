<?php

/**
 * AppserverIo\Authenticator\FormAuthenticatorTest
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Open Software License (OSL 3.0)
 * that is available through the world-wide-web at this URL:
 * http://opensource.org/licenses/osl-3.0.php
 *
 * PHP version 5
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2016 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/authenticator
 * @link      http://www.appserver.io
 */

namespace AppserverIo\Authenticator;

use AppserverIo\Lang\String;

/**
 * Test for the provider wrapper implementation.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2016 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/authenticator
 * @link      http://www.appserver.io
 */
class FormAuthenticatorTest extends \PHPUnit_Framework_TestCase
{

    /**
     * Test if the login() method works as expected.
     *
     * @return void
     */
    public function testLogin()
    {

        // initialize mock servlet request/principal
        $mockServletRequest = $this->getMock('AppserverIo\Authenticator\Http\HttpServletRequestInterface');
        $mockPrincipal = $this->getMock('AppserverIo\Psr\Security\PrincipalInterface');

        // initialize a mock realm
        $mockRealm = $this->getMockBuilder($realmInterface = 'AppserverIo\Psr\Auth\RealmInterface')
                          ->setMethods(get_class_methods($realmInterface))
                          ->getMock();
        $mockRealm->expects($this->once())
                  ->method('authenticate')
                  ->with($username = new String('appserver'), $password = new String('appserver.i0'))
                  ->willReturn($mockPrincipal);

        // initialize a mock login configuration
        $mockConfigData = $this->getMockBuilder($loginConfigurationInterface = 'AppserverIo\Psr\Auth\LoginConfigurationInterface')
                               ->setMethods(get_class_methods($loginConfigurationInterface))
                               ->getMock();
        $mockConfigData->expects($this->once())
                       ->method('getRealmName')
                       ->willReturn($realmName = 'my-test-realm');

        // initialize a mock authentication manager
        $mockAuthenticationManager = $this->getMockBuilder($authenticationManagerInterface = 'AppserverIo\Psr\Auth\AuthenticationManagerInterface')
                                          ->setMethods(get_class_methods($authenticationManagerInterface))
                                          ->getMock();
        $mockAuthenticationManager->expects($this->once())
                                  ->method('getRealm')
                                  ->with($realmName)
                                  ->willReturn($mockRealm);

        // initialize a mock authenticator node configuration
        $mockAuthenticatorNode = $this->getMockBuilder($authenticatorNodeInterface = 'AppserverIo\Appserver\Core\Api\Node\AuthenticatorNodeInterface')
                                      ->setMethods(get_class_methods($authenticatorNodeInterface))
                                      ->getMock();

        // initialize the authenticator
        $authenticator = new FormAuthenticator($mockConfigData, $mockAuthenticationManager, $mockAuthenticatorNode);

        // test the authenticator's login() method
        $this->assertInstanceOf(
            'AppserverIo\Psr\Security\PrincipalInterface',
            $authenticator->login($username, $password, $mockServletRequest)
        );
    }
}
