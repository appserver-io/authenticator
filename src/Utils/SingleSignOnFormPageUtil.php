<?php

/**
 * AppserverIo\Authenticator\Utils\SingleSignOnFormPageUtil
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

namespace AppserverIo\Authenticator\Utils;

use AppserverIo\Psr\Security\SecurityException;
use AppserverIo\Psr\Auth\LoginConfigurationInterface;
use AppserverIo\Psr\Auth\AuthenticationManagerInterface;
use AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface;
use AppserverIo\Psr\Application\ManagerConfigurationInterface;
use AppserverIo\Authenticator\Utils\ParamKeys;
use AppserverIo\Server\Dictionaries\ServerVars;

/**
 * Utility class that helps to read the login form page configuration.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2016 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/authenticator
 * @link      http://www.appserver.io
 */
class SingleSignOnFormPageUtil implements FormPageUtilInterface
{

    /**
     * The general form page utility instance.
     *
     * @var \AppserverIo\Authenticator\Utils\FormPageUtilInterface
     */
    protected $formPageUtil;

    /**
     * Initializes the utiltiy with the general form page utility instance.
     *
     * @param \AppserverIo\Authenticator\Utils\FormPageUtilInterface $formPageUtil the general form page utility instance
     */
    public function __construct(FormPageUtilInterface $formPageUtil)
    {
        $this->formPageUtil = $formPageUtil;
    }

    /**
     * Return's the location for the redirect to the login page configured in the `web.xml` file.
     *
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface $servletRequest        The servlet request instance
     * @param \AppserverIo\Psr\Auth\LoginConfigurationInterface         $configData            The login configuration in the `web.xml`
     * @param \AppserverIo\Psr\Auth\AuthenticationManagerInterface|null $authenticationManager The authentication manager instance
     *
     * @return string The location for the redirect to the login page
     * @throws \AppserverIo\Psr\Security\SecurityException Is thrown, if the appropriate form configuration in the `web.xml` is missing
     */
    public function getLoginPage(
        HttpServletRequestInterface $servletRequest,
        LoginConfigurationInterface $configData,
        AuthenticationManagerInterface $authenticationManager = null
    ) {

        // we need an authentication manager instance here
        if ($authenticationManager === null) {
            throw new SecurityException('Can\'t find mandatory authentication manager instance as 3rd method param');
        }

        // load the manager configuration from the authentication manager
        /** @var \AppserverIo\Psr\Application\ManagerConfigurationInterface $managerConfiguration */
        $managerConfiguration = $authenticationManager->getManagerConfiguration();

        // load the URL of the identity provider and the authorization path
        $identityUrl = $managerConfiguration->getParam(ParamKeys::IDENTITY_URL);
        $authorizePath = $managerConfiguration->getParam(ParamKeys::AUTHORIZATION_PATH);

        // create the location with the redirect URI to use
        $location = sprintf('%s%s', $identityUrl, $authorizePath);

        // prepare the redirect URK with the actual scheme HTTP/HTTPS and the server name
        $redirectUri = sprintf(
            '%s://%s',
            $servletRequest->getServerVar(ServerVars::REQUEST_SCHEME),
            $servletRequest->getServerVar(ServerVars::SERVER_NAME)
        );
        // load the actual server port, because by default and in local
        // environments we often use 9080/9443 instead of 80/443
        $serverPort = (int) $servletRequest->getServerVar(ServerVars::SERVER_PORT);

        // append the port, if we do NOT have one of the default ports
        $redirectUri = in_array($serverPort, [80, 443]) ? $redirectUri : sprintf('%s:%d', $redirectUri, $serverPort);

        // append the path from the `web.xml` we've to to redirect to
        $redirectUri = sprintf('%s%s', $redirectUri, $this->formPageUtil->getLoginPage($servletRequest, $configData));

        // create the location with the redirect URI to use and return it
        return sprintf($location, $redirectUri);
    }
}
