<?php

namespace Drupal\oauth2_client\Service;

use Drupal\oauth2_client\Exception\InvalidOauth2ClientException;
use League\OAuth2\Client\Token\AccessTokenInterface;

/**
 * Base class for OAuth2 Client services.
 */
abstract class Oauth2ClientServiceBase implements Oauth2ClientServiceInterface {

  /**
   * The OAuth2 Client plugin manager.
   *
   * @var \Drupal\oauth2_client\PluginManager\Oauth2ClientPluginManagerInterface
   */
  protected $oauth2ClientPluginManager;

  /**
   * {@inheritdoc}
   */
  public function getClient($pluginId) {
    $clients = &drupal_static(__CLASS__ . '::' . __FUNCTION__, []);
    if (!isset($clients[$pluginId])) {
      $definition = $this->oauth2ClientPluginManager->getDefinition($pluginId);
      if (!$definition || !isset($definition['id'])) {
        throw new InvalidOauth2ClientException($pluginId);
      }

      $clients[$pluginId] = $this->oauth2ClientPluginManager->createInstance($definition['id']);
    }

    return $clients[$pluginId];
  }

  /**
   * {@inheritdoc}
   */
  public function retrieveAccessToken($pluginId) {
    $client = $this->getClient($pluginId);
    $token = $client->retrieveAccessToken();
    if ($token instanceof AccessTokenInterface) {
      return $token;
    }
    return NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function clearAccessToken($pluginId) {
    $client = $this->getClient($pluginId);
    $client->clearAccessToken();
  }

}
