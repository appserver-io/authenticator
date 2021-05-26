<?php

/**
 * AppserverIo\Authenticator\Utils\FormPageUtil
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

/**
 * Utility class that helps to read the login form page configuration.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2016 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/authenticator
 * @link      http://www.appserver.io
 */
class FormPageUtil implements FormPageUtilInterface
{

    /**
     * Return's the location for the redirect to the login page configured in the `web.xml` file.
     *
     * @param \AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface $servletRequest The servlet request instance
     * @param \AppserverIo\Psr\Auth\LoginConfigurationInterface         $configData     The login configuration in the `web.xml`
     *
     * @return string The location for the redirect to the login page
     * @throws \AppserverIo\Psr\Security\SecurityException Is thrown, if the appropriate form configuration in the `web.xml` is missing
     */
    public function getLoginPage(
        HttpServletRequestInterface $servletRequest,
        LoginConfigurationInterface $configData
    ) {

        // query whether or not we've a valid form login configuration
        if ($formLoginConfig = $configData->getFormLoginConfig()) {
            if ($formLoginPage = $formLoginConfig->getFormLoginPage()) {
                // initialize the location to redirect to
                $location = $formLoginPage->__toString();
                if ($baseModifier = $servletRequest->getBaseModifier()) {
                    $location = $baseModifier . $location;
                }
                // return the location
                return $location;
            }
        }

        // throw an exception because we need
        // the appropriate configuration
        throw new SecurityException(
            'Please configure a form-login-page when using auth-method \'Form\' in the login-config of your application\'s web.xml'
        );
    }
}
