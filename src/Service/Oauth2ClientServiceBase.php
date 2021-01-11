<?php

namespace Drupal\oauth2_client\Service;

use Drupal\oauth2_client\Exception\InvalidOauth2ClientException;

/**
 * Base class for OAuth2 Client services.
 */
abstract class Oauth2ClientServiceBase implements Oauth2ClientServiceInterface {

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
    return $this->state->get('oauth2_client_access_token-' . $pluginId);
  }

  /**
   * {@inheritdoc}
   */
  public function clearAccessToken($pluginId) {
    return $this->state->delete('oauth2_client_access_token-' . $pluginId);
  }

}
