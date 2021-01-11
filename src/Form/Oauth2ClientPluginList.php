<?php

namespace Drupal\oauth2_client\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Link;
use Drupal\Core\Url;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Provides a OAuth2 Client form.
 */
class Oauth2ClientPluginList extends FormBase {

  /**
   * The Drupal state api.
   *
   * @var \Drupal\oauth2_client\PluginManager\Oauth2ClientPluginManager
   */
  protected $pluginManager;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    $instance = parent::create($container);
    $instance->pluginManager = $container->get('oauth2_client.plugin_manager');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'oauth2_client_oauth2_client_plugin_list';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $header = [
      [
        'data' => $this->t('Name'),
        'field' => 'name',
        'sort' => 'desc',
      ],
      [
        'data' => $this->t('Grant Type'),
        'field' => 'grant_type',
        'class' => [RESPONSIVE_PRIORITY_MEDIUM],
      ],
      [
        'data' => $this->t('Operations'),
      ],
    ];

    $definitions = $this->pluginManager->getDefinitions();
    $rows = [];

    foreach ($definitions as $definition) {
      $url = Url::fromRoute('oauth2_client.oauth2_client_plugin_config', ['plugin' => $definition['id']]);
      $link = Link::fromTextAndUrl($this->t('Configure'), $url);
      $rows[] = [
        'data' => [
          ['data' => $definition['name']],
          ['data' => $definition['grant_type']],
          ['data' => $link->toRenderable() + ['#attributes' => ['class' => ['button']]]],
        ],
      ];
    }

    $form['oauth2_clients'] = [
      '#type' => 'table',
      '#header' => $header,
      '#rows' => $rows,
      '#empty' => $this->t('No clients available.'),
    ];
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    // This method is never called and is here for interface compatibility.
    $this->messenger()->addStatus($this->t('To configure a client, click the "Configure" button.'));
  }

}
