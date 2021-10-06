<?php

/**
 * AppserverIo\Authenticator\BearerAuthenticator
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
use AppserverIo\Psr\Auth\RealmInterface;
use AppserverIo\Psr\HttpMessage\Protocol;
use AppserverIo\Psr\Security\PrincipalInterface;
use AppserverIo\Psr\Servlet\ServletException;
use AppserverIo\Psr\Servlet\Utils\RequestHandlerKeys;
use AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface;
use AppserverIo\Psr\Servlet\Http\HttpServletResponseInterface;

/**
 * A bearer token based authenticator implementation.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2016 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/authenticator
 * @link      http://www.appserver.io
 */
class BearerAuthenticator extends AbstractAuthenticator
{

    /**
     * Defines the auth type which should match the client request type definition
     *
     * @var string AUTH_TYPE
     */
    const AUTH_TYPE = 'Bearer';

    /**
     * Returns the parsed password.
     *
     * @return \AppserverIo\Lang\String The password
     */
    public function getPassword()
    {
        return new String();
    }

    /**
     * Return's the array with the login credentials.
     *
     * @return \AppserverIo\Lang\String[] The array with the login credentials
     */
    protected function getCredentials()
    {
        return array($this->getUsername(), $this->getPassword());
    }

    /**
     * Try to authenticate the user making this request, based on the specified login configuration.
     *
     * Return TRUE if any specified constraint has been satisfied, or FALSE if we have created a response
     * challenge already.
     *
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface  $servletRequest  The servlet request instance
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletResponseInterface $servletResponse The servlet response instance
     *
     * @return boolean TRUE if authentication has already been processed on a request before, else FALSE
     * @throws \AppserverIo\Http\Authentication\AuthenticationException Is thrown if the request can't be authenticated
     */
    public function authenticate(HttpServletRequestInterface $servletRequest, HttpServletResponseInterface $servletResponse)
    {

        // invoke the onCredentials callback to load the credentials from the request
        $this->onCredentials($servletRequest, $servletResponse);

        // load the realm to authenticate this request for
        /** @var AppserverIo\Appserver\ServletEngine\Security\RealmInterface $realm */
        $realm = $this->getAuthenticationManager()->getRealm($this->getRealmName());

        // authenticate the request and initialize the user principal
        $userPrincipal = call_user_func_array(array($realm, 'authenticate'), $this->getCredentials());

        // query whether or not the realm returned an authenticated user principal
        if ($userPrincipal == null) {
            // invoke the onFailure callback and forward the user to the error page
            $this->onFailure($realm, $servletRequest, $servletResponse);
            return false;
        }

        // invoke the onSuccess callback and redirect the user to the original page
        $this->onSuccess($userPrincipal, $servletRequest, $servletResponse);
        return false;
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

        // try to load the access token from the request instead
        if ($servletRequest->hasHeader(Protocol::HEADER_AUTHORIZATION)) {
            // extract the access token from the authorization header
            sscanf($servletRequest->getHeader(Protocol::HEADER_AUTHORIZATION), 'Bearer %s', $accessToken);
            $this->username = new String($accessToken);
        }
    }

    /**
     * Will be invoked when login fails for some reasons.
     *
     * @param \AppserverIo\Appserver\ServletEngine\Security\RealmInterface $realm           The realm instance containing the exception stack
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface    $servletRequest  The servlet request instance
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletResponseInterface   $servletResponse The servlet response instance
     *
     * @return void
     */
    protected function onFailure(
        RealmInterface $realm,
        HttpServletRequestInterface $servletRequest,
        HttpServletResponseInterface $servletResponse
    ) {
        $this->forwardToErrorPage($servletRequest, $servletResponse);
    }

    /**
     * Will be invoked on a successfull login.
     *
     * @param \AppserverIo\Psr\Security\PrincipalInterface               $userPrincipal   The user principal logged into the system
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface  $servletRequest  The servlet request instance
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletResponseInterface $servletResponse The servlet response instance
     *
     * @return void
     */
    protected function onSuccess(
        PrincipalInterface $userPrincipal,
        HttpServletRequestInterface $servletRequest,
        HttpServletResponseInterface $servletResponse
    ) {

        // add the user principal and the authentication type to the request
        $this->register($servletRequest, $servletResponse, $userPrincipal);
    }

    /**
     * Register's the user principal and the authenticytion in the request and session.
     *
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface  $servletRequest  The servlet request instance
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletResponseInterface $servletResponse The servlet response instance
     * @param \AppserverIo\Psr\Security\PrincipalInterface               $userPrincipal   The actual user principal
     *
     * @return void
     */
    protected function register(
        HttpServletRequestInterface $servletRequest,
        HttpServletResponseInterface $servletResponse,
        PrincipalInterface $userPrincipal
    ) {

        // add the user principal and the authentication type to the request
        $servletRequest->setUserPrincipal($userPrincipal);
        $servletRequest->setAuthType($this->getAuthType());
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
        $servletRequest->setDispatched(true);
        $servletResponse->setHeaders($this->getDefaultHeaders());
        $servletResponse->appendBodyStream($this->serialize(array('error' => 'Use SSO server to aquire a valid access token')));
        $servletResponse->setStatusCode(500);
    }

    /**
     * Forward's the request to the configured error page.
     *
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface  $servletRequest  The servlet request instance
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletResponseInterface $servletResponse The servlet response instance
     *
     * @return void
     */
    protected function forwardToErrorPage(
        HttpServletRequestInterface $servletRequest,
        HttpServletResponseInterface $servletResponse
    ) {
        $servletRequest->setDispatched(true);
        $servletResponse->setHeaders($this->getDefaultHeaders());
        $servletResponse->appendBodyStream($this->serialize(array('error' => 'You need an valid access token to use the API')));
        $servletResponse->setStatusCode(401);
    }

    /**
     * Return's the default headers to set.
     *
     * @return string[] The array with the headers
     */
    protected function getDefaultHeaders()
    {
        return array(Protocol::HEADER_CONTENT_TYPE => 'application/json');
    }

    /**
     * Serialize's the passed value an return's it.
     *
     * @param mixed $value The value that has to be serialized
     *
     * @return string The serialized value
     */
    protected function serialize($value)
    {
        return json_encode($value);
    }

    /**
     * Tries the login the passed username/password combination for the login configuration.
     *
     * @param \AppserverIo\Lang\String                                  $username       The username used to login
     * @param \AppserverIo\Lang\String                                  $password       The password used to authenticate the user
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface $servletRequest The servlet request instance
     *
     * @return \AppserverIo\Psr\Security\PrincipalInterface The authenticated user principal
     */
    public function login(
        String $username,
        String $password,
        HttpServletRequestInterface $servletRequest
    ) {

        // load the realm to authenticate this request for
        /** @var AppserverIo\Appserver\ServletEngine\Security\RealmInterface $realm */
        $realm = $this->getAuthenticationManager()->getRealm($this->getRealmName());

        // authenticate the request and initialize the user principal
        $userPrincipal = call_user_func_array(array($realm, 'authenticate'), array($username, $password));

        // query whether or not we can authenticate the user
        if ($userPrincipal == null) {
            throw new ServletException(sprintf('Can\'t authenticate user %s', $username));
        }

        // add the user principal and the authentication type to the request
        $servletRequest->setUserPrincipal($userPrincipal);
        $servletRequest->setAuthType($this->getAuthType());

        // return's the user principal
        return $userPrincipal;
    }

    /**
     * Logout the actual user from the session.
     *
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface $servletRequest The servlet request instance
     *
     * @return void
     */
    public function logout(HttpServletRequestInterface $servletRequest)
    {
    }
}
