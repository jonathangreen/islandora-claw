<?php

namespace Drupal\islandora\EventSubscriber;

use Drupal\jwt\Authentication\Event\JwtAuthValidateEvent;
use Drupal\jwt\Authentication\Event\JwtAuthValidEvent;
use Drupal\jwt\Authentication\Event\JwtAuthGenerateEvent;
use Drupal\jwt\Authentication\Event\JwtAuthEvents;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Class JwtEventSubscriber.
 *
 * @package Drupal\islandora\EventSubscriber
 */
class JwtEventSubscriber implements EventSubscriberInterface {

  /**
   * The entity manager used to load users.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityManager;

  /**
   * The current user.
   *
   * @var \Drupal\Core\Session\AccountInterface
   */
  protected $currentUser;

  /**
   * Constructor.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_manager
   *   The entity manager service.
   * @param \Drupal\Core\Session\AccountInterface $user
   *   The current user.
   */
  public function __construct(
    EntityTypeManagerInterface $entity_manager,
    AccountInterface $user
  ) {
    $this->entityManager = $entity_manager;
    $this->currentUser = $user;
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[JwtAuthEvents::VALIDATE][] = ['validate'];
    $events[JwtAuthEvents::VALID][] = ['loadUser'];
    $events[JwtAuthEvents::GENERATE][] = ['setIslandoraClaims'];

    return $events;
  }

  /**
   * Sets claims for a Islandora consumer on the JWT.
   *
   * @param \Drupal\jwt\Authentication\Event\JwtAuthGenerateEvent $event
   *   The event.
   */
  public function setIslandoraClaims(JwtAuthGenerateEvent $event) {
    global $base_secure_url;

    // Standard claims, validated at JWT validation time.
    $event->addClaim('iat', time());
    $event->addClaim('exp', strtotime('+2 hour'));

    // Islandora claims we need to validate.
    $event->addClaim(['drupal', 'uid'], $this->currentUser->id());
    $event->addClaim(['drupal', 'name'], $this->currentUser->getAccountName());
    $event->addClaim(['drupal', 'roles'], $this->currentUser->getRoles(FALSE));
    $event->addClaim(['drupal', 'url'], $base_secure_url);
  }

  /**
   * Validates that the Islandora data is present in the JWT.
   *
   * @param \Drupal\jwt\Authentication\Event\JwtAuthValidateEvent $event
   *   A JwtAuth event.
   */
  public function validate(JwtAuthValidateEvent $event) {
    $token = $event->getToken();

    $uid = $token->getClaim(['drupal', 'uid']);
    $name = $token->getClaim(['drupal', 'name']);
    $roles = $token->getClaim(['drupal', 'roles']);
    $url = $token->getClaim(['drupal', 'url']);
    if ($uid === NULL || $name === NULL || $roles === NULL || $url === NULL) {
      $event->invalidate("Expected data missing from payload.");
    }

    $user = $this->entityManager->getStorage('user')->load($uid);
    if ($user === NULL) {
      $event->invalidate("Specified UID does not exist.");
    }
    if ($user->getAccountName() !== $name) {
      $event->invalidate("Account name does not match.");
    }
  }

  /**
   * Load and set a Drupal user to be authentication based on the JWT's uid.
   *
   * @param \Drupal\jwt\Authentication\Event\JwtAuthValidEvent $event
   *   A JwtAuth event.
   */
  public function loadUser(JwtAuthValidEvent $event) {
    $token = $event->getToken();
    $user_storage = $this->entityManager->getStorage('user');
    $uid = $token->getClaim(['drupal', 'uid']);
    $user = $user_storage->load($uid);
    $event->setUser($user);
  }

}
