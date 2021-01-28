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
  public function getAccessToken($clientId) {
    $accessToken = $this->retrieveAccessToken($clientId);
    if ($accessToken instanceof AccessTokenInterface) {
      $expirationTimestamp = $accessToken->getExpires();
      if (!empty($expirationTimestamp) && $accessToken->hasExpired()) {
        $provider = $this->getProvider($clientId);
        $newAccessToken = $provider->getAccessToken('refresh_token', [
          'refresh_token' => $accessToken->getRefreshToken(),
        ]);

        $this->storeAccessToken($clientId, $newAccessToken);
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function getGrantProvider($clientId) {
    return $this->getProvider($clientId);
  }

}
