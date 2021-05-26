<?php

/**
 * AppserverIo\Authenticator\AbstractAuthenticator
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

use Rhumsaa\Uuid\Uuid;
use AppserverIo\Lang\Boolean;
use AppserverIo\Psr\Auth\AuthenticatorInterface;
use AppserverIo\Psr\Auth\LoginConfigurationInterface;
use AppserverIo\Psr\Auth\AuthenticationManagerInterface;
use AppserverIo\Appserver\Core\Api\Node\AuthenticatorNodeInterface;

/**
 * Abstract authenticator base class providing generic functionality.
 *
 * @author    Tim Wagner <tw@appserver.io>
 * @copyright 2016 TechDivision GmbH <info@appserver.io>
 * @license   http://opensource.org/licenses/osl-3.0.php Open Software License (OSL 3.0)
 * @link      https://github.com/appserver-io/authenticator
 * @link      http://www.appserver.io
 */
abstract class AbstractAuthenticator implements AuthenticatorInterface
{

    /**
     * Mark's the authenticator as the default one.
     *
     * @var \AppserverIo\Lang\Boolean
     */
    protected $defaultAuthenticator;

    /**
     * The authentication manager instance.
     *
     * @var \AppserverIo\Psr\Auth\AuthenticationManagerInterface
     */
    protected $authenticationManager;

    /**
     * Holds the configuration data given for authentication type.
     *
     * @var \AppserverIo\Psr\Auth\LoginConfigurationInterface
     */
    protected $configData;

    /**
     * The authenticator configuration.
     *
     * @var \AppserverIo\Appserver\Core\Api\Node\AuthenticatorNodeInterface
     */
    protected $authenticatorConfiguration;

    /**
     * The name of the user to authenticate.
     *
     * @var string
     */
    protected $username;

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

        // initialize the authenticator with the passed values
        $this->configData = $configData;
        $this->authenticationManager = $authenticationManager;
        $this->authenticatorConfiguration = $authenticatorConfiguration;

        // query whether or not the default flag has been passed
        if ($configData->getDefaultAuthenticator()) {
            $this->defaultAuthenticator = new Boolean($configData->getDefaultAuthenticator()->__toString());
        } else {
            $this->defaultAuthenticator = new Boolean(false);
        }
    }

    /**
     * Return's the authenticator's UUID.
     *
     * @return string The UUID
     * @deprecated since 1.1.29
     */
    public function getSerial()
    {
        return $this->getRealmName();
    }

    /**
     * Returns the configuration data given for authentication type.
     *
     * @return \AppserverIo\Psr\Auth\LoginConfigurationInterface The configuration data
     */
    public function getConfigData()
    {
        return $this->configData;
    }

    /**
     * The authenticator configuration instance.
     *
     * @return \AppserverIo\Appserver\Core\Api\Node\AuthenticatorNodeInterface The authenticator configuration instance
     */
    public function getAuthenticatorConfiguration()
    {
        return $this->authenticatorConfiguration;
    }

    /**
     * Return's the authentication manager instance.
     *
     * @return \AppserverIo\Psr\Auth\AuthenticationManagerInterface The authentication manager instance
     */
    public function getAuthenticationManager()
    {
        return $this->authenticationManager;
    }

    /**
     * Returns the authentication type token.
     *
     * @return string
     */
    public function getAuthType()
    {
        return static::AUTH_TYPE;
    }

    /**
     * Return's the realm name.
     *
     * @return string The realm name
     */
    public function getRealmName()
    {
        return $this->getConfigData()->getRealmName();
    }

    /**
     * Returns the parsed username.
     *
     * @return string|null The username
     */
    public function getUsername()
    {
        return isset($this->username) ? $this->username : null;
    }

    /**
     * Mark's the authenticator as the default one.
     *
     * @return void
     */
    public function setDefaultAuthenticator()
    {
        $this->defaultAuthenticator = new Boolean(true);
    }

    /**
     * Query whether or not this is the default authenticator.
     *
     * @return boolean TRUE if this is the default authenticator, else FALSE
     */
    public function isDefaultAuthenticator()
    {
        return $this->defaultAuthenticator->booleanValue();
    }
}
