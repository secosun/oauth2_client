<?php

namespace Drupal\oauth2_client\Service;

use Drupal\key\Entity\Key;
use Drupal\key\KeyRepositoryInterface;
use Drupal\Core\State\StateInterface;
use Drupal\oauth2_client\Plugin\Oauth2Client\Oauth2ClientPluginInterface;

/**
 * Class KeyProvider.
 *
 * @package Drupal\oauth2_client\Service
 */
class CredentialProvider {

  /**
   * Key module service conditionally injected.
   *
   * @var \Drupal\key\KeyRepositoryInterface
   */
  protected $keyRepository;

  /**
   * The Drupal state api.
   *
   * @var \Drupal\Core\State\StateInterface
   */
  protected $state;

  /**
   * KeyService constructor.
   *
   * @param \Drupal\Core\State\StateInterface $state
   *   The key value store to use.
   */
  public function __construct(StateInterface $state) {
    $this->state = $state;
  }

  /**
   * Provides a means to our services.yml file to conditionally inject service.
   *
   * @param \Drupal\key\KeyRepositoryInterface $repository
   *   The injected service, if it exists.
   */
  public function setKeyRepository(KeyRepositoryInterface $repository) {
    $this->keyRepository = $repository;
  }

  /**
   * Detects if key module service was injected.
   *
   * @return bool
   *   True if the KeyRepository is present.
   */
  public function additionalProviders() {
    return $this->keyRepository instanceof KeyRepositoryInterface;
  }

  /**
   * Get the provided credentials.
   *
   * @param \Drupal\oauth2_client\Plugin\Oauth2Client\Oauth2ClientPluginInterface $plugin
   *   An authorization plugin.
   *
   * @return array|string
   *   The value of the configured key.
   */
  public function getCredentials(Oauth2ClientPluginInterface $plugin) {
    $provider = $plugin->getCredentialProvider();
    $credentials = [];
    if (empty($provider)) {
      return $credentials;
    }
    switch ($provider) {
      case 'key':
        $keyEntity = $this->keyRepository->getKey($plugin->getStorageKey());
        if ($keyEntity instanceof Key) {
          // A key was found in the repository.
          $credentials = $keyEntity->getKeyValues();
        }
        break;

      default:
        $credentials = $this->state->get($plugin->getStorageKey());
    }

    return $credentials;
  }

}
