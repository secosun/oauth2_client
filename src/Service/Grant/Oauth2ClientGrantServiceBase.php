<?php

namespace Drupal\oauth2_client\Service\Grant;

use Drupal\Core\Routing\UrlGeneratorInterface;
use Drupal\Core\State\StateInterface;
use Drupal\oauth2_client\PluginManager\Oauth2ClientPluginManager;
use Drupal\oauth2_client\Service\Oauth2ClientServiceBase;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Base class for OAuth2 Client grant services.
 */
abstract class Oauth2ClientGrantServiceBase extends Oauth2ClientServiceBase implements Oauth2ClientGrantServiceInterface {
  /**
   * The Request Stack.
   *
   * @var \Symfony\Component\HttpFoundation\Request
   */
  protected $currentRequest;

  /**
   * The Drupal state.
   *
   * @var \Drupal\Core\State\StateInterface
   */
  protected $state;

  /**
   * The URL generator service.
   *
   * @var \Drupal\Core\Routing\UrlGeneratorInterface
   */
  protected $urlGenerator;

  /**
   * The OAuth2 Client plugin manager.
   *
   * @var \Drupal\oauth2_client\PluginManager\Oauth2ClientPluginManager
   */
  protected $oauth2ClientPluginManager;

  /**
   * Client provider cache.
   *
   * @var array
   */
  protected $clientProviderCache;

  /**
   * Construct an OAuth2Client object.
   *
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The Request Stack.
   * @param \Drupal\Core\State\StateInterface $state
   *   The Drupal state.
   * @param \Drupal\Core\Routing\UrlGeneratorInterface $urlGenerator
   *   The URL generator service.
   * @param \Drupal\oauth2_client\PluginManager\Oauth2ClientPluginManager $oauth2ClientPluginManager
   *   The OAuth2 Client plugin manager.
   */
  public function __construct(
    RequestStack $requestStack,
    StateInterface $state,
    UrlGeneratorInterface $urlGenerator,
    Oauth2ClientPluginManager $oauth2ClientPluginManager
  ) {
    $this->currentRequest = $requestStack->getCurrentRequest();
    $this->state = $state;
    $this->urlGenerator = $urlGenerator;
    $this->oauth2ClientPluginManager = $oauth2ClientPluginManager;
    $this->clientProviderCache = [];
  }

  /**
   * Creates a new provider object.
   *
   * @param string $pluginId
   *   The client for which a provider should be created.
   *
   * @return \League\OAuth2\Client\Provider\GenericProvider
   *   The provider of the OAuth2 Server.
   *
   * @throws \Drupal\oauth2_client\Exception\InvalidOauth2ClientException
   *   Exception thrown when trying to retrieve a non-existent OAuth2 Client.
   */
  protected function getProvider($pluginId) {
    if (isset($this->clientProviderCache[$pluginId])) {
      $provider = $this->clientProviderCache[$pluginId];
    }
    else {
      $client = $this->getClient($pluginId);

      $provider = new GenericProvider([
        'clientId' => $client->getClientId(),
        'clientSecret' => $client->getClientSecret(),
        'redirectUri' => $client->getRedirectUri(),
        'urlAuthorize' => $client->getAuthorizationUri(),
        'urlAccessToken' => $client->getTokenUri(),
        'urlResourceOwnerDetails' => $client->getResourceUri(),
        'scopes' => $client->getScopes(),
        'scopeSeparator' => $client->getScopeSeparator(),
      ]);
      $this->clientProviderCache[$pluginId] = $provider;
    }
    return $provider;
  }

  /**
   * Store an access token using plugin specific storage.
   *
   * @param string $pluginId
   *   The client for which a provider should be created.
   * @param \League\OAuth2\Client\Token\AccessTokenInterface $accessToken
   *   The Access Token to be stored.
   */
  protected function storeAccessToken($pluginId, AccessTokenInterface $accessToken) {
    $client = $this->oauth2ClientPluginManager->createInstance($pluginId);
    $client->storeAccessToken($accessToken);
  }

}
