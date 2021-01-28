<?php

namespace Drupal\oauth2_client_example_plugins\Plugin\Oauth2Client;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Session\AccountInterface;
use Drupal\oauth2_client\Plugin\Oauth2Client\Oauth2ClientPluginAccessInterface;
use Drupal\oauth2_client\Plugin\Oauth2Client\Oauth2ClientPluginBase;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Auth code with access example.
 *
 * @Oauth2Client(
 *   id = "authcode_access_example",
 *   name = @Translation("Example for code capture access override"),
 *   grant_type = "authorization_code",
 *   authorization_uri = "https://oauth.mocklab.io/oauth/authorize",
 *   token_uri = "https://oauth.mocklab.io/oauth/token",
 *   resource_owner_uri = "https://oauth.mocklab.io/userinfo",
 * )
 */
class AuthCodeAccessExample extends Oauth2ClientPluginBase implements Oauth2ClientPluginAccessInterface {

  /**
   * Access Token storage implementation.
   *
   * @var \Drupal\Core\TempStore\PrivateTempStore
   */
  private $tempStore;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->tempStore = $container->get('tempstore.private')->get('authcode_private_temp_store_example');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function codeRouteAccess(AccountInterface $account) {
    return AccessResult::allowedIfHasPermissions($account, ['access content']);
  }

  /*
   * This example assumes that a user is authenticating against a third-party
   * service to retrieve a token that Drupal can use to access resources on
   * that user's behalf.
   *
   */

  /**
   * {@inheritdoc}
   */
  public function storeAccessToken(AccessToken $accessToken) {
    $key = 'oauth2_client_access_token-' . $this->getId();
    $this->tempStore->set($key, $accessToken);
  }

  /**
   * {@inheritdoc}
   */
  public function retrieveAccessToken() {
    $key = 'oauth2_client_access_token-' . $this->getId();
    return $this->tempStore->get($key);
  }

  /**
   * {@inheritdoc}
   */
  public function clearAccessToken() {
    $key = 'oauth2_client_access_token-' . $this->getId();
    return $this->tempStore->delete($key);
  }

}
