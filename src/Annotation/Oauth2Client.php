<?php

namespace Drupal\oauth2_client\Annotation;

use Drupal\Component\Annotation\Plugin;

/**
 * Annotation definition Oauth2Client plugins.
 *
 * @Annotation
 */
class Oauth2Client extends Plugin {

  /**
   * The OAuth 2 plugin ID.
   *
   * @var string
   */
  public $id;

  /**
   * The human-readable name of the OAuth2 Client.
   *
   * @var \Drupal\Core\Annotation\Translation
   *
   * @ingroup plugin_translatable
   */
  public $name;

  /**
   * The grant type of the OAuth2 authorization.
   *
   * Possible values are authorization_code, client_credentials, resource_owner.
   *
   * @var string
   */
  public $grant_type;

  /**
   * The authorization endpoint of the OAuth2 server.
   *
   * @var string
   */
  public $authorization_uri;

  /**
   * The token endpoint of the OAuth2 server.
   *
   * @var string
   */
  public $token_uri;

  /**
   * The resource endpoint of the OAuth2 Server.
   *
   * @var string
   */
  public $resource_uri;

  /**
   * The Resource Owner Details endpoint.
   *
   * @var string
   */
  public $resource_owner_uri;

  /**
   * The set of scopes for the provider to use by default.
   *
   * @var array|string|null
   */
  public $scopes;

  /**
   * The separator used to join the scopes in the OAuth2 query string.
   *
   * @var string|null
   */
  public $scope_separator;

  /**
   * A flag that may be used by Oauth2ClientPluginInterface::storeAccessToken.
   *
   * Implementations may conditionally display a message on successful storage.
   *
   * @var bool
   */
  public $success_message;

}
