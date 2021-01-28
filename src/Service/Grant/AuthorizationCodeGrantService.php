<?php

namespace Drupal\oauth2_client\Service\Grant;

use Drupal\Core\Routing\UrlGeneratorInterface;
use Drupal\Core\State\StateInterface;
use Drupal\Core\TempStore\PrivateTempStoreFactory;
use Drupal\Core\Url;
use Drupal\oauth2_client\Plugin\Oauth2Client\Oauth2ClientPluginRedirectInterface;
use Drupal\oauth2_client\PluginManager\Oauth2ClientPluginManagerInterface;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Handles Authorization Grants for the OAuth2 Client module.
 */
class AuthorizationCodeGrantService extends Oauth2ClientGrantServiceBase {

  /**
   * The Drupal tempstore.
   *
   * @var \Drupal\Core\TempStore\PrivateTempStore
   */
  protected $tempstore;

  /**
   * Construct an OAuth2Client object.
   *
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The Request Stack.
   * @param \Drupal\Core\State\StateInterface $state
   *   The Drupal state.
   * @param \Drupal\Core\Routing\UrlGeneratorInterface $urlGenerator
   *   The URL generator service.
   * @param \Drupal\oauth2_client\PluginManager\Oauth2ClientPluginManagerInterface $oauth2ClientPluginManager
   *   The OAuth2 Client plugin manager.
   * @param \Drupal\Core\TempStore\PrivateTempStoreFactory $tempstoreFactory
   *   The Drupal private tempstore factory.
   */
  public function __construct(
    RequestStack $requestStack,
    StateInterface $state,
    UrlGeneratorInterface $urlGenerator,
    Oauth2ClientPluginManagerInterface $oauth2ClientPluginManager,
    PrivateTempStoreFactory $tempstoreFactory
  ) {
    parent::__construct($requestStack, $state, $urlGenerator, $oauth2ClientPluginManager);

    $this->tempstore = $tempstoreFactory->get('oauth2_client');
  }

  /**
   * {@inheritdoc}
   */
  public function getAccessToken($clientId) {
    $provider = $this->getProvider($clientId);
    // Get the authorization URL. This also generates the state.
    $authorization_url = $provider->getAuthorizationUrl();

    // Save the state to Drupal's tempstore.
    $this->tempstore->set('oauth2_client_state-' . $clientId, $provider->getState());
    if ($this->currentRequest->hasSession()) {
      // If we have a session, save before redirect.
      $this->currentRequest->getSession()->save();
    }
    // Redirect to the authorization URL.
    $redirect = new RedirectResponse($authorization_url);
    $redirect->send();
    exit();
  }

  /**
   * Executes an authorization_code grant request with the give code.
   *
   * @param string $clientId
   *   The client plugin id.
   * @param string $code
   *   The authorization code.
   *
   * @return bool
   *   Was a valid token retrieved?
   *
   * @throws \Drupal\oauth2_client\Exception\InvalidOauth2ClientException
   *   Exception thrown when trying to retrieve a non-existent OAuth2 Client.
   */
  public function requestAccessToken($clientId, $code) {
    $provider = $this->getProvider($clientId);
    // Try to get an access token using the authorization code grant.
    try {
      $accessToken = $provider->getAccessToken('authorization_code', [
        'code' => $code,
      ]);
      if ($accessToken instanceof AccessTokenInterface) {
        $this->storeAccessToken($clientId, $accessToken);
        return TRUE;
      }
    }
    catch (IdentityProviderException $e) {
      watchdog_exception('OAuth2 Client', $e);
    }
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function getGrantProvider($clientId) {
    return $this->getProvider($clientId);
  }

  /**
   * Provide a redirect for use following authorization code capture.
   *
   * @param string $clientId
   *   The client plugin id.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   The redirect response.
   */
  public function getPostCaptureRedirect($clientId) {
    $clientPlugin = $this->getClient($clientId);
    if ($clientPlugin instanceof Oauth2ClientPluginRedirectInterface) {
      return $clientPlugin->getPostCaptureRedirect();
    }
    $url = Url::fromRoute('oauth2_client.oauth2_client_plugin_list');
    return new RedirectResponse($url->toString(TRUE)->getGeneratedUrl());
  }

}
