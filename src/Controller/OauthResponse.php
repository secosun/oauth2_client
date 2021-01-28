<?php

namespace Drupal\oauth2_client\Controller;

use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Controller to process an authorization code request.
 *
 * @package Drupal\oauth2_client\Controller
 */
class OauthResponse extends ControllerBase {

  /**
   * Injected service.
   *
   * @var \Symfony\Component\HttpFoundation\Request
   */
  protected $currentRequest;

  /**
   * The route match.
   *
   * @var \Drupal\Core\Routing\RouteMatchInterface
   */
  protected $routeMatch;

  /**
   * Injected service.
   *
   * @var \Drupal\Core\Messenger\Messenger
   */
  protected $messenger;

  /**
   * Injected client service.
   *
   * @var \Drupal\oauth2_client\Service\Grant\AuthorizationCodeGrantService
   */
  protected $grantService;

  /**
   * The Drupal tempstore.
   *
   * @var \Drupal\Core\TempStore\PrivateTempStore
   */
  protected $tempstore;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    $instance = parent::create($container);
    $instance->grantService = $container->get('oauth2_client.service.grant.authorization_code');
    $instance->messenger = $container->get('messenger');
    $instance->routeMatch = $container->get('current_route_match');
    $requestStack = $container->get('request_stack');
    $instance->currentRequest = $requestStack->getCurrentRequest();
    $instance->tempstore = $container->get('tempstore.private')->get('oauth2_client');
    return $instance;
  }

  /**
   * Route response method for validating and capturing a returned code.
   *
   * @throws \Drupal\Core\TempStore\TempStoreException
   * @throws \Drupal\oauth2_client\Exception\InvalidOauth2ClientException
   */
  public function code() {
    $pluginId = $this->routeMatch->getParameter('plugin');
    $code = $this->currentRequest->query->get('code');
    if (empty($code)) {
      throw new \UnexpectedValueException("The code query parameter is missing.");
    }
    $state = $this->currentRequest->query->get('state');
    if (empty($state)) {
      throw new \UnexpectedValueException("The state query parameter is missing.");
    }
    $storedState = $this->tempstore->get('oauth2_client_state-' . $pluginId);
    if ($state === $storedState) {
      $this->grantService->requestAccessToken($pluginId, $code);
    }
    else {
      // Potential CSRF attack. Bail out.
      $this->tempstore->delete('oauth2_client_state-' . $pluginId);
    }
    return $this->grantService->getPostCaptureRedirect($pluginId);
  }

}
