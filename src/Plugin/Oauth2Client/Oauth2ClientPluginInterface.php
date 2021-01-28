<?php

namespace Drupal\oauth2_client\Plugin\Oauth2Client;

use Drupal\Component\Plugin\ConfigurableInterface;
use Drupal\Component\Plugin\PluginInspectionInterface;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Drupal\Core\Plugin\PluginFormInterface;
use League\OAuth2\Client\Token\AccessToken;

/**
 * Interface for Oauth2 Client plugins.
 */
interface Oauth2ClientPluginInterface extends PluginInspectionInterface, ContainerFactoryPluginInterface, PluginFormInterface, ConfigurableInterface {

  /**
   * Retrieves the human-readable name of the Oauth2 Client plugin.
   *
   * @return string
   *   The name of the plugin.
   */
  public function getName();

  /**
   * Retrieves the id of the OAuth2 Client plugin.
   *
   * @return string
   *   The id of the plugin.
   */
  public function getId();

  /**
   * Retrieves the grant type of the plugin.
   *
   * @return string
   *   Possible values:
   *   - authorization_code
   *   - client_credentials
   *   - refresh_token
   *   - resource_owner
   */
  public function getGrantType();

  /**
   * Retrieves the client_id of the OAuth2 server.
   *
   * @return string
   *   The client_id of the OAuth2 server.
   */
  public function getClientId();

  /**
   * Retrieves the client_secret of the OAuth2 server.
   *
   * @return string
   *   The client_secret of the OAuth2 server.
   */
  public function getClientSecret();

  /**
   * Retrieves the redirect_uri of the OAuth2 server.
   *
   * @return string
   *   The redirect_uri of the OAuth2 server.
   */
  public function getRedirectUri();

  /**
   * Retrieves the authorization_uri of the OAuth2 server.
   *
   * @return string
   *   The authorization_uri of the OAuth2 server.
   */
  public function getAuthorizationUri();

  /**
   * Retrieves the token_uri of the OAuth2 server.
   *
   * @return string
   *   The authorization_uri of the OAuth2 server.
   */
  public function getTokenUri();

  /**
   * Retrieves the resource_uri of the OAuth2 server.
   *
   * @return string
   *   The resource_uri of the OAuth2 server.
   */
  public function getResourceUri();

  /**
   * Get the set of scopes for the provider to use by default.
   *
   * @return array|string|null
   *   The list of scopes for the provider to use.
   */
  public function getScopes();

  /**
   * Get the separator used to join the scopes in the OAuth2 query string.
   *
   * @return string|null
   *   The scopes separator to join the list of scopes in the query string.
   */
  public function getScopeSeparator();

  /**
   * Returns the plugin credentials if they are set, otherwise returns NULL.
   *
   * @return string|null
   *   The data.
   */
  public function getCredentialProvider();

  /**
   * Returns the credential storage key if it is set, otherwise returns NULL.
   *
   * @return mixed|null
   *   The data.
   */
  public function getStorageKey();

  /**
   * Stores access tokens obtained by this client.
   *
   * @param \League\OAuth2\Client\Token\AccessToken $accessToken
   *   The token to store.
   */
  public function storeAccessToken(AccessToken $accessToken);

  /**
   * Retrieve the access token storage.
   *
   * @return mixed
   *   The stored token, or NULL if no value exists.
   */
  public function retrieveAccessToken();

  /**
   * Clears the access token from storage.
   */
  public function clearAccessToken();

  /**
   * Check the plugin definition for success_message or return a static value.
   *
   * @return bool
   *   Should a success message be displayed to the user?
   */
  public function displaySuccessMessage();

}
