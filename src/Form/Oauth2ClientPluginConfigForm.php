<?php

namespace Drupal\oauth2_client\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Form\SubformState;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Configure OAuth2 Client settings for this site.
 */
class Oauth2ClientPluginConfigForm extends FormBase {

  /**
   * The plugin being configured.
   *
   * @var \Drupal\oauth2_client\Plugin\Oauth2Client\Oauth2ClientPluginInterface
   */
  protected $plugin;

  /**
   * The Drupal state api.
   *
   * @var \Drupal\Core\State\StateInterface
   */
  protected $state;

  /**
   * Injected client service.
   *
   * @var \Drupal\oauth2_client\Service\Oauth2ClientService
   */
  protected $clientService;

  /**
   * The messenger service.
   *
   * @var \Drupal\Core\Messenger\MessengerInterface
   */
  protected $messenger;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    $instance = parent::create($container);
    $routeMatch = $instance->getRouteMatch();
    $pluginId = $routeMatch->getParameter('plugin');
    /** @var \Drupal\oauth2_client\PluginManager\Oauth2ClientPluginManager $pluginManager */
    $pluginManager = $container->get('oauth2_client.plugin_manager');
    $config = $instance->configFactory()->get('oauth2_client.credentials.' . $pluginId)->getRawData();
    $instance->plugin = $pluginManager->createInstance($pluginId, $config);
    $instance->state = $container->get('state');
    $instance->clientService = $container->get('oauth2_client.service');
    $instance->messenger = $container->get('messenger');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'oauth2_client_oauth2_client_plugin_config';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $form['title'] = [
      '#type' => 'html_tag',
      '#tag' => 'h2',
      '#value' => $this->plugin->getName(),
    ];

    $form['plugin'] = [];
    $subformState = SubformState::createForSubform($form['plugin'], $form, $form_state);
    $form['plugin'] = $this->plugin->buildConfigurationForm($form['plugin'], $subformState);
    $form['plugin']['#tree'] = TRUE;

    $form['actions']['#type'] = 'actions';
    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => $this->t('Save configuration'),
      '#button_type' => 'primary',
    ];

    // By default, render the form using system-config-form.html.twig.
    $form['#theme'] = 'system_config_form';
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    $subformState = SubformState::createForSubform($form['plugin'], $form, $form_state);
    $this->plugin->validateConfigurationForm($form['plugin'], $subformState);
    parent::validateForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $subformState = SubformState::createForSubform($form['plugin'], $form, $form_state);
    $this->plugin->submitConfigurationForm($form['plugin'], $subformState);
    // Try to obtain a token.
    try {
      // Clear the existing token.
      $this->clientService->clearAccessToken($this->plugin->getId());
      $values = $form_state->getValues();
      $provider = $values['plugin']['credential_provider'];
      $credentials = $values['plugin'][$provider];
      $user = $credentials['username'] ?? NULL;
      $password = $credentials['password'] ?? NULL;
      $token = $this->clientService->getAccessToken($this->plugin->getId(), $user, $password);
      if ($token instanceof AccessTokenInterface) {
        $form_state->setRedirect('oauth2_client.oauth2_client_plugin_list');
        $this->messenger->addStatus(
          $this->t('OAuth token obtained from remote website and stored.')
        );
      }
    }
    catch (IdentityProviderException $e) {
      // Failed to get the access token.
      // Reset original configuration.
      $this->messenger->addError(
        $this->t(
          'Unable to obtain an OAuth token. The error message is: @message',
          ['@message' => $e->getMessage()]
        )
      );
    }
  }

}
