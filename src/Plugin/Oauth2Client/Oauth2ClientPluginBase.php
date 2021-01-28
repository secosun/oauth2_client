<?php

namespace Drupal\oauth2_client\Plugin\Oauth2Client;

use Drupal\Component\Utility\NestedArray;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Form\ConfigFormBaseTrait;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Messenger\MessengerInterface;
use Drupal\Core\Plugin\PluginBase;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\State\StateInterface;
use Drupal\Core\Url;
use Drupal\oauth2_client\Service\CredentialProvider;
use Drupal\oauth2_client\Exception\Oauth2ClientPluginMissingKeyException;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Base class for Oauth2Client plugins.
 */
abstract class Oauth2ClientPluginBase extends PluginBase implements Oauth2ClientPluginInterface {
  use ConfigFormBaseTrait;


  /**
   * The configuration factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * Injected credential service.
   *
   * @var \Drupal\oauth2_client\Service\CredentialProvider
   */
  protected $credentialService;

  /**
   * The Drupal state api.
   *
   * @var \Drupal\Core\State\StateInterface
   */
  protected $state;

  /**
   * Injected UUID service.
   *
   * @var \Drupal\Component\Uuid\UuidInterface
   */
  protected $uuid;

  /**
   * Storage for credentials retrieved from credential service.
   *
   * @var array
   */
  private $credentials;

  /**
   * The messenger service.
   *
   * @var \Drupal\Core\Messenger\MessengerInterface
   */
  protected $messenger;

  /**
   * Constructs a Oauth2ClientPluginBase object.
   *
   * @param array $configuration
   *   The plugin configuration.
   * @param string $plugin_id
   *   The plugin ID.
   * @param mixed $plugin_definition
   *   The plugin definitions.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The configuration factory service.
   * @param \Drupal\oauth2_client\Service\CredentialProvider $credProvider
   *   Injected credential service.
   * @param \Drupal\Core\State\StateInterface $state
   *   Injected state service.
   * @param \Drupal\Component\Uuid\UuidInterface $uuid
   *   Injected UUID service.
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   Injected message service.
   */
  final public function __construct(
    array $configuration,
    $plugin_id,
    $plugin_definition,
    ConfigFactoryInterface $configFactory,
    CredentialProvider $credProvider,
    StateInterface $state,
    UuidInterface $uuid,
    MessengerInterface $messenger
  ) {
    parent::__construct($configuration, $plugin_id, $plugin_definition);

    $this->configFactory = $configFactory;
    $this->credentialService = $credProvider;
    $this->state = $state;
    $this->uuid = $uuid;
    $this->messenger = $messenger;
    $this->clearCredentials();
    $this->loadConfiguration($configuration);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('config.factory'),
      $container->get('oauth2_client.service.credentials'),
      $container->get('state'),
      $container->get('uuid'),
      $container->get('messenger')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function defaultConfiguration() {
    return [
      'uuid' => $this->uuid->generate(),
      'credentials' => [],
    ];
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return ['oauth2_client.credentials.' . $this->getId()];
  }

  /**
   * {@inheritdoc}
   */
  public function getConfiguration() {
    return $this->configuration;
  }

  /**
   * Helper function to initialize the internal configuration array.
   *
   * @param array $configuration
   *   Provided configuration.
   * @param bool $save
   *   Flags if the loaded configuration should also be saved.
   */
  protected function loadConfiguration(array $configuration, $save = FALSE) {
    $configName = 'oauth2_client.credentials.' . $this->getId();
    $config = $this->config($configName);
    $savedConfig = $config->getRawData();
    $this->configuration = NestedArray::mergeDeep(
      $this->defaultConfiguration(),
      $savedConfig,
      $configuration
    );
    if ($save) {
      foreach ($this->configuration as $key => $value) {
        $config->set($key, $value);
      }
      $config->save();
    }
  }

  /**
   * {@inheritdoc}
   */
  public function setConfiguration(array $configuration) {
    $this->loadConfiguration($configuration, TRUE);
  }

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(
    array $form,
    FormStateInterface $form_state
  ) {
    $credentials = $this->retrieveCredentials();
    $grantType = $this->getGrantType();
    $form = [
      'credential_provider' => [
        '#type' => 'hidden',
        '#value' => 'oauth2_client',
      ],
      'oauth2_client' => [
        '#type' => 'fieldset',
        '#title' => $this->t('Stored locally'),
        'client_id' => [
          '#type' => 'textfield',
          '#title' => $this->t('Client ID'),
          '#default_value' => $credentials['client_id'] ?? '',
        ],
        'client_secret' => [
          '#type' => 'textfield',
          '#title' => $this->t('Client secret'),
          '#default_value' => $credentials['client_secret'] ?? '',
        ],
      ],
    ];
    if ($grantType == 'resource_owner') {
      $form['oauth2_client']['username'] = [
        '#type' => 'textfield',
        '#title' => $this->t('Username'),
        '#description' => $this->t('The username and password entered here are not saved, but are only used to request the token.'),
      ];
      $form['oauth2_client']['password'] = [
        '#type' => 'password',
        '#title' => $this->t('Password'),
      ];
    }
    // If Key module or some other future additional provider is available:
    if ($this->credentialService->additionalProviders()) {
      $this->expandedProviderOptions($form);
    }
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateConfigurationForm(array &$form, FormStateInterface $form_state) {
    $values = $form_state->getValues();
    if (empty($values['credential_provider'])) {
      $form_state->setError(
        $form['credential_provider'],
        'A credential provider is required.'
      );
    }
    else {
      $provider = $values['credential_provider'];
      foreach ($values[$provider] as $key => $value) {
        if (empty($value)) {
          $form_state->setError(
            $form[$provider][$key],
            'All credential values are required.'
          );
        }
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitConfigurationForm(array &$form, FormStateInterface $form_state) {
    $configuration = $this->getConfiguration();
    $values = $form_state->getValues();
    $provider = $values['credential_provider'];
    $credentials = $values[$provider];
    array_walk($credentials, function (&$value) {
      $value = trim($value);
    });
    $key = $configuration['uuid'];
    if ($provider == 'key') {
      $key = $credentials['id'];
    }
    $configuration['credentials'] = [
      'credential_provider' => $provider,
      'storage_key' => $key,
    ];
    $this->setConfiguration($configuration);
    if ($provider == 'oauth2_client') {
      // Remove the username and password.
      if (isset($credentials['username'])) {
        unset($credentials['username']);
      }
      if (isset($credentials['password'])) {
        unset($credentials['password']);
      }
      $this->state->set($configuration['uuid'], $credentials);
    }
  }

  /**
   * {@inheritdoc}
   */
  public function getName() {
    $this->checkKeyDefined('name');

    return $this->pluginDefinition['name'];
  }

  /**
   * {@inheritdoc}
   */
  public function getId() {
    $this->checkKeyDefined('id');

    return $this->pluginDefinition['id'];
  }

  /**
   * {@inheritdoc}
   */
  public function getClientId() {
    $credentials = $this->retrieveCredentials();
    if (empty($credentials['client_id'])) {
      throw new Oauth2ClientPluginMissingKeyException('client_id');
    }

    return $credentials['client_id'];
  }

  /**
   * {@inheritdoc}
   */
  public function getClientSecret() {
    $credentials = $this->retrieveCredentials();
    if (empty($credentials['client_secret'])) {
      throw new Oauth2ClientPluginMissingKeyException('client_secret');
    }

    return $credentials['client_secret'];
  }

  /**
   * {@inheritdoc}
   */
  public function getGrantType() {
    $this->checkKeyDefined('grant_type');

    return $this->pluginDefinition['grant_type'];
  }

  /**
   * {@inheritdoc}
   */
  public function getRedirectUri() {
    $url = Url::fromRoute(
      'oauth2_client.code',
      ['plugin' => $this->getId()],
      ['absolute' => TRUE]
    );
    return $url->toString(TRUE)->getGeneratedUrl();
  }

  /**
   * {@inheritdoc}
   */
  public function getAuthorizationUri() {
    $this->checkKeyDefined('authorization_uri');

    return $this->pluginDefinition['authorization_uri'];
  }

  /**
   * {@inheritdoc}
   */
  public function getTokenUri() {
    $this->checkKeyDefined('token_uri');

    return $this->pluginDefinition['token_uri'];
  }

  /**
   * {@inheritdoc}
   */
  public function getResourceUri() {
    $this->checkKeyDefined('resource_owner_uri');

    return $this->pluginDefinition['resource_owner_uri'];
  }

  /**
   * {@inheritdoc}
   */
  public function getScopes() {
    if (!isset($this->pluginDefinition['scopes'])) {
      return [];
    }

    return $this->pluginDefinition['scopes'] ?: [];
  }

  /**
   * {@inheritdoc}
   */
  public function getScopeSeparator() {
    if (!isset($this->pluginDefinition['scope_separator'])) {
      return ',';
    }

    return $this->pluginDefinition['scope_separator'];
  }

  /**
   * Check that a key is defined when requested. Throw an exception if not.
   *
   * @param string $key
   *   The key to check.
   *
   * @throws \Drupal\oauth2_client\Exception\Oauth2ClientPluginMissingKeyException
   *   Thrown if the key being checked is not defined.
   */
  private function checkKeyDefined($key) {
    if (!isset($this->pluginDefinition[$key])) {
      throw new Oauth2ClientPluginMissingKeyException($key);
    }
  }

  /**
   * Helper function to retrieve and cache credentials.
   *
   * @return array
   *   The credentials array.
   */
  private function retrieveCredentials() {
    if (empty($this->credentials)) {
      $this->credentials = $this->credentialService->getCredentials($this);
    }
    return $this->credentials;
  }

  /**
   * Helper function to clear cached credentials.
   */
  private function clearCredentials() {
    $this->credentials = [];
  }

  /**
   * Helper method to build the credential provider elements of the form.
   *
   * Only needed if we have more than one provider.  Currently supporting
   * oauth2_client controlled local storage and Key module controlled optional
   * storage.
   *
   * @param array $form
   *   The configuration form.
   */
  protected function expandedProviderOptions(array &$form) {
    $provider = $this->getCredentialProvider();
    $grantType = $this->getGrantType();
    // Provide selectors for the api key credential provider.
    $form['credential_provider'] = [
      '#type' => 'select',
      '#title' => $this->t('Credential provider'),
      '#default_value' => empty($provider) ? 'oauth2_client' : $provider,
      '#options' => [
        'oauth2_client' => $this->t('Local storage'),
        'key' => $this->t('Key module'),
      ],
      '#attributes' => [
        'data-states-selector' => 'provider',
      ],
      '#weight' => -99,
    ];
    $form['oauth2_client']['#states'] = [
      'required' => [
        ':input[data-states-selector="provider"]' => ['value' => 'oauth2_client'],
      ],
      'visible' => [
        ':input[data-states-selector="provider"]' => ['value' => 'oauth2_client'],
      ],
      'enabled' => [
        ':input[data-states-selector="provider"]' => ['value' => 'oauth2_client'],
      ],
    ];
    $key_id = $provider == 'key' ? $this->getStorageKey() : '';
    $form['key'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Managed by the Key module'),
      '#states' => [
        'required' => [
          ':input[data-states-selector="provider"]' => ['value' => 'key'],
        ],
        'visible' => [
          ':input[data-states-selector="provider"]' => ['value' => 'key'],
        ],
        'enabled' => [
          ':input[data-states-selector="provider"]' => ['value' => 'key'],
        ],
      ],
      'id' => [
        '#type' => 'key_select',
        '#title' => $this->t('Select a stored Key'),
        '#default_value' => $key_id,
        '#empty_option' => $this->t('- Please select -'),
        '#key_filters' => ['type' => 'oauth2_client'],
        '#description' => $this->t('Select the key you have configured to hold the Oauth credentials.'),
      ],
    ];
    if ($grantType == 'resource_owner') {
      $form['key']['username'] = [
        '#type' => 'textfield',
        '#title' => $this->t('Username'),
        '#description' => $this->t('The username and password entered here are not saved, but are only used to request the token.'),
      ];
      $form['key']['password'] = [
        '#type' => 'password',
        '#title' => $this->t('Password'),
      ];
    }
  }

  /**
   * {@inheritdoc}
   */
  public function getCredentialProvider() {
    $configuration = $this->getConfiguration();
    return $configuration['credentials']['credential_provider'] ?? NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function getStorageKey() {
    $configuration = $this->getConfiguration();
    return $configuration['credentials']['storage_key'] ?? NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function displaySuccessMessage() {
    return $this->pluginDefinition['success_message'] ?? FALSE;
  }

}
