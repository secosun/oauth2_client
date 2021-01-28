<?php

namespace Drupal\oauth2_client_example_plugins\Plugin\Oauth2Client;

use Drupal\oauth2_client\Plugin\Oauth2Client\Oauth2ClientPluginBase;
use League\OAuth2\Client\Token\AccessToken;

/**
 * Auth code example.
 *
 * @Oauth2Client(
 *   id = "authcode_example",
 *   name = @Translation("Example for Authorization Code grant"),
 *   grant_type = "authorization_code",
 *   authorization_uri = "https://oauth.mocklab.io/oauth/authorize",
 *   token_uri = "https://oauth.mocklab.io/oauth/token",
 *   resource_owner_uri = "https://oauth.mocklab.io/userinfo",
 *   success_message = TRUE
 * )
 */
class AuthCodeExample extends Oauth2ClientPluginBase {

  /*
   * This example assumes that the Drupal site is using a shared resource
   * from a third-party service that provides a service to all uses of the site.
   *
   * Storing a single AccessToken in state for the plugin shares access to the
   * external resource for ALL users of this plugin.
   */

  /**
   * {@inheritdoc}
   */
  public function storeAccessToken(AccessToken $accessToken) {
    $this->state->set('oauth2_client_access_token-' . $this->getId(), $accessToken);
    if ($this->displaySuccessMessage()) {
      $this->messenger->addStatus(
        $this->t('OAuth token stored.')
      );
    }
  }

  /**
   * {@inheritdoc}
   */
  public function retrieveAccessToken() {
    return $this->state->get('oauth2_client_access_token-' . $this->getId());
  }

  /**
   * {@inheritdoc}
   */
  public function clearAccessToken() {
    $this->state->delete('oauth2_client_access_token-' . $this->getId());
  }

}
