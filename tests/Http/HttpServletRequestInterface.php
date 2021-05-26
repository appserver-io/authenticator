<?php

/**
 * AppserverIo\Authenticator\HttpServletRequestInterface
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

namespace AppserverIo\Authenticator\Http;

use AppserverIo\Psr\Security\PrincipalInterface;

/**
 * Test for the provider wrapper implementation.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2016 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/authenticator
 * @link      http://www.appserver.io
 */
interface HttpServletRequestInterface extends \AppserverIo\Psr\Servlet\Http\HttpServletRequestInterface
{

    /**
     * Set's the user principal for this request.
     *
     * @param \AppserverIo\Psr\Security\PrincipalInterface|null $userPrincipal The user principal
     *
     * @return void
     */
    public function setUserPrincipal(PrincipalInterface $userPrincipal = null);
}