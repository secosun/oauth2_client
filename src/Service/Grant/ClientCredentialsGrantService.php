<?php

namespace Drupal\oauth2_client\Service\Grant;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

/**
 * Handles Authorization Grants for the OAuth2 Client module.
 */
class ClientCredentialsGrantService extends Oauth2ClientGrantServiceBase {

  /**
   * {@inheritdoc}
   */
  public function getAccessToken($pluginId) {
    $provider = $this->getProvider($pluginId);

    try {
      $accessToken = $provider->getAccessToken('client_credentials');

      $this->storeAccessToken($pluginId, $accessToken);
    }
    catch (IdentityProviderException $e) {
      // Failed to get the access token.
      watchdog_exception('OAuth2 Client', $e);
    }
  }

  /**
   * {@inheritdoc}
   */
  public function getGrantProvider($pluginId) {
    return $this->getProvider($pluginId);
  }

}
