<?php

namespace Drupal\oauth2_client\Service\Grant;

/**
 * Handles Authorization Grants for the OAuth2 Client module.
 */
class ResourceOwnersCredentialsGrantService extends Oauth2ClientGrantServiceBase {

  /**
   * Storage for usernames and passwords keyed by plugin id.
   *
   * @var array
   */
  protected $usernamesPasswords;

  /**
   * {@inheritdoc}
   */
  public function getAccessToken($pluginId) {
    $provider = $this->getProvider($pluginId);
    $credentials = $this->getUsernamePassword($pluginId);
    if (empty($credentials)) {
      throw new \RuntimeException('Missing username and password for client plugin ' . $pluginId);
    }
    try {
      $accessToken = $provider->getAccessToken('password', [
        'username' => $credentials['username'],
        'password' => $credentials['password'],
      ]);

      $this->storeAccessToken($pluginId, $accessToken);
    }
    catch (\Exception $e) {
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

  /**
   * Pass credentials in memory to be used in the oauth request.
   *
   * It may not be necessary, but storing by client id in case some edge
   * case has two or more client plugins operating on the same request.
   *
   * @param string $pluginId
   *   The id of the Oauth2Client plugin implementing this grant type.
   * @param string $username
   *   Optional - The username if needed by the grant type.
   * @param string $password
   *   Optional - The password if needed by the grant type.
   */
  public function setUsernamePassword($pluginId, $username, $password) {
    $this->usernamesPasswords[$pluginId] = [
      'username' => $username,
      'password' => $password,
    ];
  }

  /**
   * Gets credential pairs by plugin id.
   *
   * @param string $pluginId
   *   The id of the Oauth2Client plugin implementing this grant type.
   *
   * @return array
   *   Associative array with `username` and `password` keys.
   */
  protected function getUsernamePassword($pluginId) {
    return $this->usernamesPasswords[$pluginId] ?? [];
  }

}
