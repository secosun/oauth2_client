<?php

namespace Drupal\oauth2_client\Service\Grant;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

/**
 * Handles Authorization Grants for the OAuth2 Client module.
 */
class ResourceOwnersCredentialsGrantService extends Oauth2ClientGrantServiceBase {


  /**
   * Get an OAuth2 access token using Resource Owners grant.
   *
   * The username & password are optional for backwards compatibility on the
   * previously designed interface but this request will fail without valid
   * values.
   *
   * @param string $clientId
   *   The id of the Oauth2Client plugin implementing this grant type.
   * @param string $username
   *   Optional - The username if needed by the grant type.
   * @param string $password
   *   Optional - The password if needed by the grant type.
   *
   * @throws \Drupal\oauth2_client\Exception\InvalidOauth2ClientException
   */
  public function getAccessToken($clientId, $username = '', $password = '') {
    $provider = $this->getProvider($clientId);
    $client = $this->getClient($clientId);

    try {
      $accessToken = $provider->getAccessToken('password', [
        'username' => $username,
        'password' => $password,
      ]);

      $this->storeAccessToken($clientId, $accessToken);
    }
    catch (IdentityProviderException $e) {
      // Failed to get the access token.
      watchdog_exception('OAuth2 Client', $e);
    }
  }

  /**
   * {@inheritdoc}
   */
  public function getGrantProvider($clientId) {
    return $this->getProvider($clientId);
  }

}
