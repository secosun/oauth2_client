<?php

namespace Drupal\oauth2_client\Service;

use Drupal\Core\State\StateInterface;
use Drupal\oauth2_client\PluginManager\Oauth2ClientPluginManagerInterface;
use Drupal\oauth2_client\Service\Grant\Oauth2ClientGrantServiceInterface;
use Drupal\oauth2_client\Service\Grant\ResourceOwnersCredentialsGrantService;

/**
 * The OAuth2 Client service.
 */
class Oauth2ClientService extends Oauth2ClientServiceBase {

  /**
   * The OAuth2 Client plugin manager.
   *
   * @var \Drupal\oauth2_client\PluginManager\Oauth2ClientPluginManagerInterface
   */
  protected $oauth2ClientPluginManager;

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
   * @param \Drupal\oauth2_client\Service\Grant\Oauth2ClientGrantServiceInterface $resourceOwnersCredentialsGrantService
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
   * @param string $clientId
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
   */
  public function getAccessToken($clientId, $username = '', $password = '') {
    $access_token = $this->retrieveAccessToken($clientId);
    if (!$access_token || ($access_token->getExpires() && $access_token->hasExpired())) {
      $client = $this->getClient($clientId);

      switch ($client->getGrantType()) {
        case 'authorization_code':
          $access_token = $this->getAuthorizationCodeAccessToken($clientId);
          break;

        case 'client_credentials':
          $access_token = $this->getClientCredentialsAccessToken($clientId);
          break;

        case 'resource_owner':
          $access_token = $this->getResourceOwnersCredentialsAccessToken($clientId, $username, $password);
          break;
      }
    }

    return $access_token;
  }

  /**
   * {@inheritdoc}
   */
  public function getProvider($clientId) {
    $client = $this->getClient($clientId);
    switch ($client->getGrantType()) {
      case 'client_credentials':
        $provider = $this->getClientCredentialsProvider($clientId);
        break;
      case 'resource_owner':
        $provider = $this->getResourceOwnersCredentialsProvider($clientId);
        break;
      case 'authorization_code':
      default:
        $provider = $this->getAuthorizationCodeProvider($clientId);
        break;
    }
    return $provider;
  }

  /**
   * Retrieves an access token for the 'authorization_code' grant type.
   *
   * @param string $pluginId
   *   The id of the Oauth2Client plugin implementing this grant type.
   *
   * @return \League\OAuth2\Client\Token\AccessTokenInterface
   *   The Access Token for the given client ID.
   */
  private function getAuthorizationCodeAccessToken($pluginId) {
    $stored_token = $this->retrieveAccessToken($pluginId);
    if ($stored_token) {
      if ($stored_token->getExpires() && $stored_token->hasExpired()) {
        if (empty($stored_token->getRefreshToken())) {
          # Token is expired but we have no refresh_token. Just get a new one.
          $access_token = NULL;
        }
        else {
          $access_token = $this->grantServices['refresh_token']->getAccessToken($pluginId);
        }
      }
      else {
        $access_token = $stored_token;
      }
    }
    if (empty($access_token)) {
      $access_token = $this->grantServices['authorization_code']->getAccessToken($pluginId);
    }

    return $access_token;
  }

  /**
   * Retrieves the league/oauth2-client provider for the 'authorization_code'
   * grant type.
   *
   * @param string $pluginId
   *   The id of the Oauth2Client plugin implementing this grant type.
   *
   * @return \League\OAuth2\Client\Provider\AbstractProvider
   *   The Provider for the given client ID.
   */
  private function getAuthorizationCodeProvider($pluginId) {
    return $this->grantServices['authorization_code']->getGrantProvider($pluginId);
  }

  /**
   * Retrieves an access token for the 'client_credentials' grant type.
   *
   * @param string $pluginId
   *   The id of the Oauth2Client plugin implementing this grant type.
   *
   * @return \League\OAuth2\Client\Token\AccessTokenInterface
   *   The Access Token for the given client ID.
   */
  private function getClientCredentialsAccessToken($pluginId) {
    $access_token = $this->retrieveAccessToken($pluginId);

    if (!$access_token) {
      $access_token = $this->grantServices['client_credentials']->getAccessToken($pluginId);
    }

    return $access_token;
  }

  /**
   * Retrieves the league/oauth2-client provider for the 'client_credentials'
   * grant type.
   *
   * @param string $pluginId
   *   The id of the Oauth2Client plugin implementing this grant type.
   *
   * @return \League\OAuth2\Client\Provider\AbstractProvider
   *   The Provider for the given client ID.
   */
  private function getClientCredentialsProvider($pluginId) {
    return $this->grantServices['client_credentials']->getGrantProvider($pluginId);
  }

  /**
   * Retrieves an access token for the 'resource_owner' grant type.
   *
   * @param string $pluginId
   *   The id of the Oauth2Client plugin implementing this grant type.
   * @param string $username
   *  The username if needed by the grant type.
   * @param string $password
   *   The password if needed by the grant type.
   *
   * @return \League\OAuth2\Client\Token\AccessTokenInterface
   *   The Access Token for the given client ID.
   */
  private function getResourceOwnersCredentialsAccessToken($pluginId, $username, $password) {
    $access_token = $this->retrieveAccessToken($pluginId);

    if (!$access_token) {
      $access_token = $this->grantServices['resource_owner']->getAccessToken($pluginId, $username, $password);
    }

    return $access_token;
  }

  /**
   * Retrieves the league/oauth2-client provider for the 'resource_owner' grant
   * type.
   *
   * @param $pluginId
   *   The id of the Oauth2Client plugin implementing this grant type.
   *
   * @return \League\OAuth2\Client\Provider\AbstractProvider
   *   The Provider for the given client ID.
   */
  private function getResourceOwnersCredentialsProvider($pluginId) {
    return $this->grantServices['resource_owner']->getGrantProvider($pluginId);
  }

}
