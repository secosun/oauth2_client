<?php

namespace Drupal\oauth2_client\Service;

use Drupal\Core\State\StateInterface;
use Drupal\oauth2_client\PluginManager\Oauth2ClientPluginManagerInterface;
use Drupal\oauth2_client\Service\Grant\Oauth2ClientGrantServiceInterface;
use Drupal\oauth2_client\Service\Grant\ResourceOwnersCredentialsGrantService;
use League\OAuth2\Client\Token\AccessTokenInterface;

/**
 * The OAuth2 Client service.
 */
class Oauth2ClientService extends Oauth2ClientServiceBase {

  /**
   * The Drupal state.
   *
   * @var \Drupal\Core\State\StateInterface
   */
  protected $state;

  /**
   * An array of OAuth2 Client grant services.
   *
   * @var array
   */
  protected $grantServices = [];

  /**
   * Constructs an Oauth2ClientService object.
   *
   * @param \Drupal\oauth2_client\PluginManager\Oauth2ClientPluginManagerInterface $oauth2ClientPluginManager
   *   The Oauth2 Client plugin manager.
   * @param \Drupal\Core\State\StateInterface $state
   *   The Drupal state.
   * @param \Drupal\oauth2_client\Service\Grant\Oauth2ClientGrantServiceInterface $authorizationCodeGrantService
   *   The authorization code grant service.
   * @param \Drupal\oauth2_client\Service\Grant\Oauth2ClientGrantServiceInterface $clientCredentialsGrantService
   *   The client credentials grant service.
   * @param \Drupal\oauth2_client\Service\Grant\Oauth2ClientGrantServiceInterface $refreshTokenGrantService
   *   The refresh token grant service.
   * @param \Drupal\oauth2_client\Service\Grant\ResourceOwnersCredentialsGrantService $resourceOwnersCredentialsGrantService
   *   The resource owner's credentials grant service.
   */
  public function __construct(
    Oauth2ClientPluginManagerInterface $oauth2ClientPluginManager,
    StateInterface $state,
    Oauth2ClientGrantServiceInterface $authorizationCodeGrantService,
    Oauth2ClientGrantServiceInterface $clientCredentialsGrantService,
    Oauth2ClientGrantServiceInterface $refreshTokenGrantService,
    ResourceOwnersCredentialsGrantService $resourceOwnersCredentialsGrantService
  ) {
    $this->oauth2ClientPluginManager = $oauth2ClientPluginManager;
    $this->state = $state;
    $this->grantServices = [
      'authorization_code' => $authorizationCodeGrantService,
      'client_credentials' => $clientCredentialsGrantService,
      'refresh_token' => $refreshTokenGrantService,
      'resource_owner' => $resourceOwnersCredentialsGrantService,
    ];
  }

  /**
   * Obtains an existing or a new access token.
   *
   * @param string $pluginId
   *   The Oauth2Client plugin id.
   * @param string $username
   *   Optional - The username if needed by the grant type.
   * @param string $password
   *   Optional - The password if needed by the grant type.
   *
   * @return \League\OAuth2\Client\Token\AccessTokenInterface|null
   *   Returns a token or null.
   *
   * @throws \Drupal\oauth2_client\Exception\InvalidOauth2ClientException
   *   Thrown in the upstream League library.
   */
  public function getAccessToken($pluginId, $username = '', $password = '') {
    $accessToken = $this->retrieveAccessToken($pluginId);
    if ($accessToken instanceof AccessTokenInterface) {
      $refreshToken = $accessToken->getRefreshToken();
      $expirationTimestamp = $accessToken->getExpires();
      if (!empty($expirationTimestamp) && $accessToken->hasExpired() && !empty($refreshToken)) {
        $accessToken = $this->grantServices['refresh_token']->getAccessToken($pluginId);
      }
    }
    else {
      $client = $this->getClient($pluginId);

      switch ($client->getGrantType()) {
        case 'authorization_code':
          $this->grantServices['authorization_code']->getAccessToken($pluginId);
          break;

        case 'client_credentials':
          $this->grantServices['client_credentials']->getAccessToken($pluginId);
          $accessToken = $this->retrieveAccessToken($pluginId);
          break;

        case 'resource_owner':
          $this->grantServices['resource_owner']->setUsernamePassword($pluginId, $username, $password);
          $this->grantServices['resource_owner']->getAccessToken($pluginId);
          $accessToken = $this->retrieveAccessToken($pluginId);
          break;
      }
    }

    return $accessToken;
  }

  /**
   * Obtains a Provider from the relevant service.
   *
   * @param string $pluginId
   *   The client for which a provider should be obtained.
   *
   * @return \League\OAuth2\Client\Provider\GenericProvider
   *   The provider of the OAuth2 Server.
   *
   * @throws \Drupal\oauth2_client\Exception\InvalidOauth2ClientException
   *   Thrown in the upstream League library.
   */
  public function getProvider($pluginId) {
    $client = $this->getClient($pluginId);
    return $this->grantServices[$client->getGrantType()]->getGrantProvider($pluginId);
  }

}
