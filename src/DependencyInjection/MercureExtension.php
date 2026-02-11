<?php

/*
 * This file is part of the Mercure Component project.
 *
 * (c) Kévin Dunglas <dunglas@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Symfony\Bundle\MercureBundle\DependencyInjection;

use Jose\Component\Core\JWK;
use Symfony\Bundle\MercureBundle\DataCollector\MercureDataCollector;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Alias;
use Symfony\Component\DependencyInjection\Argument\IteratorArgument;
use Symfony\Component\DependencyInjection\Compiler\AliasDeprecatedPublicServicesPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Mercure\Authorization;
use Symfony\Component\Mercure\Debug\TraceableHub;
use Symfony\Component\Mercure\Debug\TraceablePublisher;
use Symfony\Component\Mercure\Discovery;
use Symfony\Component\Mercure\EventSubscriber\SetCookieSubscriber;
use Symfony\Component\Mercure\FrankenPhpHub;
use Symfony\Component\Mercure\Hub;
use Symfony\Component\Mercure\HubInterface;
use Symfony\Component\Mercure\HubRegistry;
use Symfony\Component\Mercure\Jwt\CallableTokenProvider;
use Symfony\Component\Mercure\Jwt\DefaultClaimsTokenFactory;
use Symfony\Component\Mercure\Jwt\FactoryTokenProvider;
use Symfony\Component\Mercure\Jwt\Grant;
use Symfony\Component\Mercure\Jwt\LcobucciFactory;
use Symfony\Component\Mercure\Jwt\StaticJwtProvider;
use Symfony\Component\Mercure\Jwt\StaticTokenProvider;
use Symfony\Component\Mercure\Jwt\TokenFactoryInterface;
use Symfony\Component\Mercure\Jwt\TokenProviderInterface;
use Symfony\Component\Mercure\Jwt\WebTokenFactory;
use Symfony\Component\Mercure\Messenger\UpdateHandler;
use Symfony\Component\Mercure\ProtocolVersion;
use Symfony\Component\Mercure\Publisher;
use Symfony\Component\Mercure\PublisherInterface;
use Symfony\Component\Mercure\Twig\MercureExtension as TwigMercureExtension;
use Symfony\Component\Stopwatch\Stopwatch;
use Symfony\UX\Turbo\Bridge\Mercure\Broadcaster;
use Symfony\UX\Turbo\Bridge\Mercure\TurboStreamListenRenderer;
use Twig\Environment;
use Twig\Extension\AbstractExtension;

/**
 * @author Kévin Dunglas <dunglas@gmail.com>
 */
final class MercureExtension extends Extension
{
    public function __construct(
        private readonly ?bool $webTokenLibraryInstalled = null,
    ) {
    }

    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = $this->getConfiguration($configs, $container);
        if (!$configuration instanceof ConfigurationInterface) {
            return;
        }

        $config = $this->processConfiguration($configuration, $configs);
        if (!$config['hubs']) {
            return;
        }

        $defaultPublisher = null;
        $defaultHubId = null;
        $traceableHubs = [];
        $hubs = [];
        $defaultHubName = null;
        $enableProfiler = ($config['enable_profiler'] ?? $container->getParameter('kernel.debug')) && class_exists(Stopwatch::class);
        foreach ($config['hubs'] as $name => $hub) {
            $builtinHub = !isset($hub['url']);
            $protocolVersion = ProtocolVersion::from($hub['protocol_version']);
            $cookieName = $hub['cookie_name'];

            $tokenFactory = null;
            $tokenProvider = null;

            // Legacy "jwt" node (kept for BC, now also carrying Mercure protocol 1.0 options) —
            // produces $tokenProvider (and $tokenFactory for the secret/jwks paths).
            if (isset($hub['jwt'])) {
                if (isset($hub['jwt']['value'])) {
                    $tokenProvider = \sprintf('mercure.hub.%s.jwt.provider', $name);

                    $container->register($tokenProvider, StaticTokenProvider::class)
                        ->addArgument($hub['jwt']['value'])
                        ->addTag('mercure.jwt.provider');

                    // TODO: remove the following definition in 0.5
                    $jwtProvider = \sprintf('mercure.hub.%s.jwt_provider', $name);
                    $jwtProviderDefinition = $container->register($jwtProvider, StaticJwtProvider::class)
                        ->addArgument($hub['jwt']['value']);

                    $this->deprecate(
                        $jwtProviderDefinition,
                        'The "%service_id%" service is deprecated. You should stop using it, as it will be removed in the future, use "'.$tokenProvider.'" instead.'
                    );
                } elseif (isset($hub['jwt']['provider'])) {
                    $tokenProvider = $hub['jwt']['provider'];
                } else {
                    // 'factory', or 'secret'/'jwks_uri', must be set.
                    $factoryId = \sprintf('mercure.hub.%s.jwt.factory', $name);
                    $rawTokenFactory = $hub['jwt']['factory'] ?? $this->registerTokenFactory($container, $name, $factoryId, $hub['jwt'], $protocolVersion, 'jwt');

                    // "aud" defaults to the hub's own public identifier and, together with any explicit
                    // "jwt.claims", is baked into the factory itself (not just the provider below), so
                    // Authorization and the Twig mercure() function — which call HubInterface::getFactory()
                    // directly — get these claims too.
                    $tokenFactory = $this->applyDefaultClaims($container, $factoryId, $rawTokenFactory, $hub['jwt'], $protocolVersion, $hub);

                    $container->register('.lazy.'.$tokenFactory, TokenFactoryInterface::class)
                        ->setFactory(['Closure', 'fromCallable'])
                        ->addArgument([new Reference($tokenFactory), 'create']);
                    $tokenFactory = '.lazy.'.$tokenFactory;

                    $grants = $this->grants($hub['jwt']['publish'] ?? [], $hub['jwt']['subscribe'] ?? []);

                    $tokenProvider = \sprintf('mercure.hub.%s.jwt.provider', $name);
                    $container->register($tokenProvider, FactoryTokenProvider::class)
                        ->addArgument(new Reference($tokenFactory))
                        ->addArgument($grants)
                        ->addTag('mercure.jwt.factory');

                    $container->registerAliasForArgument($tokenFactory, TokenFactoryInterface::class, $name);
                    $container->registerAliasForArgument($tokenFactory, TokenFactoryInterface::class, "{$name}Factory");
                    $container->registerAliasForArgument(
                        $tokenFactory,
                        TokenFactoryInterface::class,
                        "{$name}TokenFactory"
                    );
                }
            } elseif (isset($hub['jwt_provider'])) {
                $jwtProvider = $hub['jwt_provider'];
                $tokenProvider = \sprintf('mercure.hub.%s.jwt.provider', $name);

                $container->register($tokenProvider, CallableTokenProvider::class)
                    ->addArgument(new Reference($jwtProvider))
                    ->addTag('mercure.jwt.provider');
            } elseif (isset($hub['publisher'])) {
                // Split publisher/subscriber JWT configuration — produces $tokenProvider (from the
                // publisher config) and, when the subscriber can sign, $tokenFactory.
                $pub = $hub['publisher'];

                if (isset($pub['value'])) {
                    $tokenProvider = \sprintf('mercure.hub.%s.jwt.provider', $name);

                    $container->register($tokenProvider, StaticTokenProvider::class)
                        ->addArgument($pub['value'])
                        ->addTag('mercure.jwt.provider');

                    // TODO: remove the following definition in 0.5
                    $jwtProvider = \sprintf('mercure.hub.%s.jwt_provider', $name);
                    $jwtProviderDefinition = $container->register($jwtProvider, StaticJwtProvider::class)
                        ->addArgument($pub['value']);

                    $this->deprecate(
                        $jwtProviderDefinition,
                        'The "%service_id%" service is deprecated. You should stop using it, as it will be removed in the future, use "'.$tokenProvider.'" instead.'
                    );
                } elseif (isset($pub['provider'])) {
                    $tokenProvider = $pub['provider'];
                } else {
                    // "factory", "secret", or "jwks_uri" — build a TokenFactoryInterface for the publisher,
                    // reused for the subscriber when both sides sign identically.
                    $sub = $hub['subscriber'] ?? [];
                    $sharedSecret = isset($pub['secret'], $sub['secret'])
                        && !isset($pub['jwks_uri']) && !isset($sub['jwks_uri'])
                        && $pub['secret'] === $sub['secret']
                        && ($pub['algorithm'] ?? null) === ($sub['algorithm'] ?? null)
                        && ($pub['passphrase'] ?? '') === ($sub['passphrase'] ?? '')
                        && ($pub['claims'] ?? []) === ($sub['claims'] ?? []);

                    // Shared signing collapses onto the canonical "mercure.hub.%s.jwt.factory" id, so a hub
                    // whose publisher and subscriber sign identically mints a single factory — exactly as
                    // the legacy "jwt.secret" path does.
                    $publisherFactoryId = $sharedSecret
                        ? \sprintf('mercure.hub.%s.jwt.factory', $name)
                        : \sprintf('mercure.hub.%s.publisher.jwt.factory', $name);

                    $rawPublisherFactory = $pub['factory'] ?? $this->registerTokenFactory($container, $name, $publisherFactoryId, $pub, $protocolVersion, 'publisher');
                    $publisherFactory = $this->applyDefaultClaims($container, $publisherFactoryId, $rawPublisherFactory, $pub, $protocolVersion, $hub);

                    $lazyPublisherFactory = '.lazy.'.$publisherFactory;
                    $container->register($lazyPublisherFactory, TokenFactoryInterface::class)
                        ->setFactory(['Closure', 'fromCallable'])
                        ->addArgument([new Reference($publisherFactory), 'create']);

                    $grants = $this->grants($pub['topics'] ?? [], $sub['topics'] ?? []);

                    $tokenProvider = \sprintf('mercure.hub.%s.jwt.provider', $name);
                    $container->register($tokenProvider, FactoryTokenProvider::class)
                        ->addArgument(new Reference($lazyPublisherFactory))
                        ->addArgument($grants)
                        ->addTag('mercure.jwt.factory');

                    // Subscriber block — produces $tokenFactory
                    if (isset($sub['factory'])) {
                        $tokenFactory = $sub['factory'];
                    } elseif ($sharedSecret) {
                        // Reuse the publisher factory.
                        $tokenFactory = $lazyPublisherFactory;
                    } elseif (isset($sub['secret']) || isset($sub['jwks_uri'])) {
                        $subscriberFactoryId = \sprintf('mercure.hub.%s.subscriber.jwt.factory', $name);
                        $rawSubscriberFactory = $this->registerTokenFactory($container, $name, $subscriberFactoryId, $sub, $protocolVersion, 'subscriber');
                        $subscriberFactory = $this->applyDefaultClaims($container, $subscriberFactoryId, $rawSubscriberFactory, $sub, $protocolVersion, $hub);

                        $tokenFactory = '.lazy.'.$subscriberFactory;
                        $container->register($tokenFactory, TokenFactoryInterface::class)
                            ->setFactory(['Closure', 'fromCallable'])
                            ->addArgument([new Reference($subscriberFactory), 'create']);
                    }

                    if (null !== $tokenFactory) {
                        $container->registerAliasForArgument($tokenFactory, TokenFactoryInterface::class, $name);
                        $container->registerAliasForArgument($tokenFactory, TokenFactoryInterface::class, "{$name}Factory");
                        $container->registerAliasForArgument(
                            $tokenFactory,
                            TokenFactoryInterface::class,
                            "{$name}TokenFactory"
                        );
                    }
                }
            }

            if (null !== $tokenProvider) {
                $container->registerAliasForArgument($tokenProvider, TokenProviderInterface::class, $name);
                $container->registerAliasForArgument($tokenProvider, TokenProviderInterface::class, "{$name}Provider");
                $container->registerAliasForArgument($tokenProvider, TokenProviderInterface::class, "{$name}TokenProvider");
            }

            $hubId = \sprintf('mercure.hub.%s', $name);
            $publisherId = \sprintf('mercure.hub.%s.publisher', $name);
            $hubs[$name] = new Reference($hubId);
            if (!$defaultPublisher && ($config['default_hub'] ?? $name) === $name) {
                $defaultHubName = $name;
                $defaultHubId = $hubId;
                $defaultPublisher = $publisherId;
            }

            if ($builtinHub) {
                $container->register($hubId, FrankenPhpHub::class)
                    ->addArgument($hub['public_url'])
                    ->addArgument($tokenFactory ? new Reference($tokenFactory) : null)
                    ->addArgument($cookieName)
                    ->addArgument($protocolVersion)
                    ->addTag('mercure.hub');
            } else {
                $container->register($hubId, Hub::class)
                    ->addArgument($hub['url'])
                    ->addArgument(new Reference($tokenProvider))
                    ->addArgument($tokenFactory ? new Reference($tokenFactory) : null)
                    ->addArgument($hub['public_url'])
                    ->addArgument(new Reference('http_client', ContainerInterface::IGNORE_ON_INVALID_REFERENCE))
                    ->addArgument($cookieName)
                    ->addArgument($protocolVersion)
                    ->addTag('mercure.hub');
            }

            if (!$builtinHub) {
                $container->registerAliasForArgument($hubId, HubInterface::class, "{$name}Hub");
                $container->registerAliasForArgument($hubId, HubInterface::class, $name);

                $publisherDefinition = $container->register($publisherId, Publisher::class)
                    ->addArgument($hub['url'])
                    ->addArgument(new Reference($tokenProvider))
                    ->addArgument(new Reference('http_client', ContainerInterface::IGNORE_ON_INVALID_REFERENCE))
                    ->addTag('mercure.publisher');

                $this->deprecate(
                    $publisherDefinition,
                    'The "%service_id%" service is deprecated. You should stop using it, as it will be removed in the future, use "'.$hubId.'" instead.'
                );

                $this->deprecate(
                    $container->registerAliasForArgument($publisherId, PublisherInterface::class, "{$name}Publisher"),
                    'The "%alias_id%" service is deprecated. You should stop using it, as it will be removed in the future, use "'.$hubId.'" instead.'
                );

                $this->deprecate(
                    $container->registerAliasForArgument($publisherId, PublisherInterface::class, $name),
                    'The "%alias_id%" service is deprecated. You should stop using it, as it will be removed in the future, use "'.$hubId.'" instead.'
                );
            }

            $bus = $hub['bus'] ?? null;
            $attributes = null === $bus ? [] : ['bus' => $hub['bus']];

            $messengerHandlerId = \sprintf('mercure.hub.%s.message_handler', $name);
            $container->register($messengerHandlerId, UpdateHandler::class)
                ->addArgument(new Reference($hubId))
                ->addTag('messenger.message_handler', $attributes);

            if ($enableProfiler) {
                if (!$builtinHub) {
                    $traceablePublisher = $container->register("$publisherId.traceable", TraceablePublisher::class)
                        ->setDecoratedService($publisherId)
                        ->addArgument(new Reference("$publisherId.traceable.inner"))
                        ->addArgument(new Reference('debug.stopwatch'));

                    $this->deprecate(
                        $traceablePublisher,
                        'The "%service_id%" service is deprecated. Use "'.$hubId.'.traceable" instead.'
                    );

                    $traceableHubs[$name] = new Reference("$publisherId.traceable");
                }

                $container->register("$hubId.traceable", TraceableHub::class)
                    ->setDecoratedService($hubId)
                    ->addArgument(new Reference("$hubId.traceable.inner"))
                    ->addArgument(new Reference('debug.stopwatch'));

                $traceableHubs[$name] = new Reference("$hubId.traceable");
            }

            if (class_exists(Broadcaster::class)) {
                $container->register("turbo.mercure.{$name}.renderer", TurboStreamListenRenderer::class)
                    ->addArgument(new Reference($hubId))
                    // uses an alias dynamically registered in a compiler pass
                    ->addArgument(new Reference('turbo.mercure.stimulus_helper'))
                    ->addArgument(new Reference('turbo.id_accessor'))
                    ->addArgument(new Reference('twig'))
                    ->addTag('turbo.renderer.stream_listen', ['transport' => $name]);

                if ($defaultHubName === $name && 'default' !== $name) {
                    $container->getDefinition("turbo.mercure.{$name}.renderer")
                        ->addTag('turbo.renderer.stream_listen', ['transport' => 'default']);
                }

                $container->register("turbo.mercure.{$name}.broadcaster", Broadcaster::class)
                    ->addArgument($name)
                    ->addArgument(new Reference($hubId))
                    ->addTag('turbo.broadcaster');
            }
        }

        if ($enableProfiler) {
            $container->register('data_collector.mercure', MercureDataCollector::class)
                ->addArgument(new IteratorArgument($traceableHubs))
                ->addTag('data_collector', [
                    'template' => '@Mercure/Collector/mercure.html.twig',
                    'id' => 'mercure',
                ]);
        }

        $container->setAlias(HubInterface::class, $defaultHubId);

        if (null !== $defaultPublisher) {
            $this->deprecate(
                $container->setAlias(Publisher::class, $defaultPublisher),
                'The "%alias_id%" service alias is deprecated. Use "'.Hub::class.'" instead.'
            );

            $this->deprecate(
                $container->setAlias(PublisherInterface::class, $defaultPublisher),
                'The "%alias_id%" service alias is deprecated. Use "'.HubInterface::class.'" instead.'
            );
        }

        $container->register(HubRegistry::class)
            ->addArgument(new Reference($defaultHubId))
            ->addArgument($hubs)
        ;

        $container->register(Authorization::class)
            ->addArgument(new Reference(HubRegistry::class))
            ->addArgument($config['default_cookie_lifetime'])
        ;

        $container->register(Discovery::class)
            ->addArgument(new Reference(HubRegistry::class))
        ;

        if (class_exists(SetCookieSubscriber::class)) {
            $container->register(SetCookieSubscriber::class)
                ->addTag('kernel.event_subscriber', ['priority' => -10]);
        }

        if (class_exists(Environment::class) && class_exists(TwigMercureExtension::class)) {
            $definition = $container->register(TwigMercureExtension::class)
                ->setArguments([new Reference(HubRegistry::class), new Reference(Authorization::class), new Reference('request_stack')]);

            if (is_a(TwigMercureExtension::class, AbstractExtension::class, true)) {
                $definition->addTag('twig.extension');
            } else {
                $definition->addTag('twig.attribute_extension')->addTag('twig.runtime');
            }
        }
    }

    /**
     * Registers, at $factoryId, the token factory built from a signing config ("jwt", "publisher" or
     * "subscriber", named by $configPath for error messages) and returns its service id.
     *
     * @param array<string, mixed> $jwt the signing sub-config: one of "secret"/"jwks_uri" plus the
     *                                  optional "algorithm"/"passphrase"/"key_id"/"claims" siblings
     */
    private function registerTokenFactory(ContainerBuilder $container, string $name, string $factoryId, array $jwt, ProtocolVersion $protocolVersion, string $configPath): string
    {
        // Fail at compile time rather than on the first minted token: RFC 9068 access tokens
        // require these claims, and LcobucciFactory's runtime exception can't point at the
        // bundle option to set. "aud" is exempt, it defaults to the hub's own URL.
        if (ProtocolVersion::V1 === $protocolVersion) {
            $missing = array_filter(['iss', 'sub', 'client_id'], static fn (string $claim): bool => empty($jwt['claims'][$claim]));
            if ([] !== $missing) {
                throw new InvalidConfigurationException(\sprintf('The "mercure.hubs.%1$s.%2$s.claims" option must define the "%3$s" claim(s): they are required by RFC 9068 access tokens when "protocol_version" is "1.0" and "%2$s.secret" or "%2$s.jwks_uri" is used.', $name, $configPath, implode('", "', $missing)));
            }
        }

        if (!isset($jwt['jwks_uri'])) {
            $container->register($factoryId, LcobucciFactory::class)
                ->addArgument($jwt['secret'])
                ->addArgument($jwt['algorithm'] ?? 'hmac.sha256')
                // RFC 9068 access tokens are expected to carry an "exp" claim; a resource server may
                // reject one that doesn't. The legacy "mercure" claim has no such expectation, so only
                // protocol 1.0 gets an automatic lifetime here, preserving the 0.x non-expiring default.
                ->addArgument(ProtocolVersion::V1 === $protocolVersion ? 0 : null)
                ->addArgument($jwt['passphrase'] ?? '')
                ->addArgument($protocolVersion)
                ->addTag('mercure.jwt.factory');

            return $factoryId;
        }

        if (!($this->webTokenLibraryInstalled ?? class_exists(JWK::class))) {
            throw new \LogicException(\sprintf('The "%1$s" hub is configured with "%2$s.jwks_uri", but the "web-token/jwt-library" package required to fetch the signing key from a JSON Web Key Set is not installed. Try running "composer require web-token/jwt-library", or configure "mercure.hubs.%1$s.%2$s.factory" to point to your own token factory service.', $name, $configPath));
        }

        $container->register($factoryId, WebTokenFactory::class)
            ->setFactory([WebTokenFactory::class, 'fromJwksUri'])
            ->setArgument('$jwksUri', $jwt['jwks_uri'])
            ->setArgument('$httpClient', new Reference('http_client', ContainerInterface::IGNORE_ON_INVALID_REFERENCE))
            ->setArgument('$algorithm', $jwt['algorithm'] ?? 'HS256')
            ->setArgument('$keyId', $jwt['key_id'] ?? null)
            // this branch only exists for protocol 1.0 (the "jwks_uri" config option requires it),
            // so, unlike LcobucciFactory's, this lifetime default is unconditional; see the comment there.
            ->setArgument('$jwtLifetime', 0)
            ->addTag('mercure.jwt.factory');

        return $factoryId;
    }

    /**
     * Wraps $rawFactory in a DefaultClaimsTokenFactory when the signing config carries "claims" (or a
     * protocol 1.0 hub has an "aud" to default), so those claims are baked into the factory itself and
     * reach HubInterface::getFactory() callers (Authorization, the Twig mercure() function). Returns the
     * wrapper's id, or $rawFactory untouched when there is nothing to merge — a 0.x hub without claims
     * keeps minting byte-identical legacy tokens, and a user-supplied factory passes through unchanged.
     *
     * @param array<string, mixed> $jwt the signing sub-config
     * @param array<string, mixed> $hub the whole hub config, for the "aud" default ("public_url"/"url")
     */
    private function applyDefaultClaims(ContainerBuilder $container, string $factoryBaseId, string $rawFactory, array $jwt, ProtocolVersion $protocolVersion, array $hub): string
    {
        $defaultClaims = $jwt['claims'] ?? [];
        if (ProtocolVersion::V1 === $protocolVersion && null !== ($aud = $hub['public_url'] ?? $hub['url'] ?? null)) {
            $defaultClaims += ['aud' => $aud];
        }

        if ([] === $defaultClaims) {
            return $rawFactory;
        }

        $wrappedFactory = $factoryBaseId.'.default_claims';
        $container->register($wrappedFactory, DefaultClaimsTokenFactory::class)
            ->addArgument(new Reference($rawFactory))
            ->addArgument($defaultClaims);

        return $wrappedFactory;
    }

    /**
     * Builds the publish/subscribe grants for a FactoryTokenProvider. Both actions are always granted,
     * even over an empty topic list, to preserve the legacy claim's exact historical shape (a "mercure"
     * object with "publish"/"subscribe" keys, always present); under protocol 1.0 an empty-topics grant
     * is inert. Inline Definitions, not live Grant instances: the compiled container can only dump an
     * argument it knows how to (re)construct, not an already-built object.
     *
     * @param array<int, string>|array<string, string[]> $publishTopics
     * @param array<int, string>|array<string, string[]> $subscribeTopics
     *
     * @return Definition[]
     */
    private function grants(array $publishTopics, array $subscribeTopics): array
    {
        return [
            new Definition(Grant::class, [[Grant::ACTION_PUBLISH], $publishTopics]),
            new Definition(Grant::class, [[Grant::ACTION_SUBSCRIBE], $subscribeTopics]),
        ];
    }

    /**
     * @param Definition|Alias $definition
     */
    private function deprecate($definition, string $message): void
    {
        if (class_exists(AliasDeprecatedPublicServicesPass::class)) {
            $definition->setDeprecated('symfony/mercure-bundle', '0.2', $message);
        } else {
            /* @phpstan-ignore-next-line */
            $definition->setDeprecated(true, $message);
        }
    }
}
