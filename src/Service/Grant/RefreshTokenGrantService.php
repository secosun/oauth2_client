<?php

namespace Drupal\oauth2_client\Service\Grant;

use League\OAuth2\Client\Token\AccessTokenInterface;

/**
 * Handles Authorization Grants for the OAuth2 Client module.
 */
class RefreshTokenGrantService extends Oauth2ClientGrantServiceBase {

  /**
   * {@inheritdoc}
   */
  public function getAccessToken($pluginId) {
    $accessToken = $this->retrieveAccessToken($pluginId);
    if ($accessToken instanceof AccessTokenInterface) {
      $expirationTimestamp = $accessToken->getExpires();
      if (!empty($expirationTimestamp) && $accessToken->hasExpired()) {
        $provider = $this->getProvider($pluginId);
        $newAccessToken = $provider->getAccessToken('refresh_token', [
          'refresh_token' => $accessToken->getRefreshToken(),
        ]);

        $this->storeAccessToken($pluginId, $newAccessToken);
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function getGrantProvider($pluginId) {
    return $this->getProvider($pluginId);
  }

}
