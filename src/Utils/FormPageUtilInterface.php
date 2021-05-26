<?php

/**
 * AppserverIo\Authenticator\Utils\FormPageUtilInterface
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

use AppserverIo\Psr\Auth\LoginConfigurationInterface;
use AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface;

/**
 * Interface for utility implementations the handle form logins.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2016 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/authenticator
 * @link      http://www.appserver.io
 */
interface FormPageUtilInterface
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
    public function getLoginPage(HttpServletRequestInterface $servletRequest, LoginConfigurationInterface $configData);
}
