<?php

/**
 * AppserverIo\Authenticator\SingleSignOnAuthenticator
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
use AppserverIo\Lang\Boolean;
use AppserverIo\Psr\HttpMessage\Protocol;
use AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface;
use AppserverIo\Psr\Servlet\Http\HttpServletResponseInterface;
use AppserverIo\Psr\Auth\LoginConfigurationInterface;
use AppserverIo\Psr\Auth\AuthenticationManagerInterface;
use AppserverIo\Authenticator\FormAuthenticator;
use AppserverIo\Authenticator\Utils\FormKeys;
use AppserverIo\Authenticator\Utils\FormPageUtil;
use AppserverIo\Authenticator\Utils\SingleSignOnFormPageUtil;
use AppserverIo\Appserver\Core\Api\Node\AuthenticatorNodeInterface;

/**
 * A form based authenticator implementation.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2016 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/authenticator
 * @link      http://www.appserver.io
 */
class SingleSignOnAuthenticator extends FormAuthenticator
{

    /**
     * Defines the auth type which should match the client request type definition
     *
     * @var string AUTH_TYPE
     */
    const AUTH_TYPE = 'SingleSignOn';

    /**
     * The authorization code to authenticate the user with.
     *
     * @var string
     */
    protected $authorizationCode;

    /**
     * The utility instance to handle SSO functionality.
     *
     * @var \AppserverIo\Authenticator\Utils\SingleSignOnUtil
     */
    protected $singleSignOnFormPageUtil;

    /**
     * Constructs the authentication type.
     *
     * @param \AppserverIo\Psr\Auth\LoginConfigurationInterface               $configData                 The configuration data for auth type instance
     * @param \AppserverIo\Psr\Auth\AuthenticationManagerInterface            $authenticationManager      The authentication manager instance
     * @param \AppserverIo\Appserver\Core\Api\Node\AuthenticatorNodeInterface $authenticatorConfiguration The authenticator configuration instance
     */
    public function __construct(
        LoginConfigurationInterface $configData,
        AuthenticationManagerInterface $authenticationManager,
        AuthenticatorNodeInterface $authenticatorConfiguration
    ) {

        // initialize the form page utility
        $this->singleSignOnFormPageUtil = new SingleSignOnFormPageUtil(new FormPageUtil());

        // pass the instances to the parent constructor
        parent::__construct($configData, $authenticationManager, $authenticatorConfiguration);
    }

    /**
     * Returns the parsed authorization code.
     *
     * @return \AppserverIo\Lang\String The authorization
     */
    public function getAuthorizationCode()
    {
        return $this->authorizationCode ? $this->authorizationCode : null;
    }

    /**
     * Return's the location for the 307 redirect to the login page.
     *
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface $servletRequest The servlet request instance
     *
     * @return string The location for the 307 redirect
     */
    protected function getLoginPage(HttpServletRequestInterface $servletRequest)
    {
        return $this->singleSignOnFormPageUtil->getLoginPage($servletRequest, $this->getConfigData(), $this->getAuthenticationManager());
    }

    /**
     * Return's the array with the login credentials.
     *
     * @return \AppserverIo\Lang\String[] The array with the login credentials
     */
    protected function getCredentials()
    {
        return array($this->getUsername(), $this->getPassword(), $this->getAuthorizationCode());
    }

    /**
     * Will be invoked to load the credentials from the request.
     *
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface  $servletRequest  The servlet request instance
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletResponseInterface $servletResponse The servlet response instance
     *
     * @return void
     */
    protected function onCredentials(
        HttpServletRequestInterface $servletRequest,
        HttpServletResponseInterface $servletResponse
    ) {

        // try to load authorization code from the request instead
        if ($servletRequest->hasParameter(FormKeys::CODE)) {
            // load authorization code from the request
            $this->authorizationCode = new String($servletRequest->getParameter(FormKeys::CODE, FILTER_UNSAFE_RAW));
        }

        // also try to load username and password
        parent::onCredentials($servletRequest, $servletResponse);
    }

    /**
     * Forward's the request to the configured login page.
     *
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface  $servletRequest  The servlet request instance
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletResponseInterface $servletResponse The servlet response instance
     *
     * @return void
     */
    protected function forwardToLoginPage(
        HttpServletRequestInterface $servletRequest,
        HttpServletResponseInterface $servletResponse
    ) {

        try {
            // load the location for the login page
            $location = $this->getLoginPage($servletRequest);
            // redirect to the configured login page
            $servletRequest->setDispatched(true);
            $servletResponse->setStatusCode(307);
            $servletResponse->addHeader(Protocol::HEADER_LOCATION, $location);
        } catch (SecurityException $se) {
            // redirect to the default error page
            $servletRequest->setAttribute(
                RequestHandlerKeys::ERROR_MESSAGE,
                $se->getMessage()
            );
            $servletRequest->setDispatched(true);
            $servletResponse->setStatusCode(500);
        }
    }
}
