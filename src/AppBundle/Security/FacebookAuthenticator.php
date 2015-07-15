<?php

namespace AppBundle\Security;

use Doctrine\ORM\EntityManager;
use KnpU\Guard\AbstractGuardAuthenticator;
use KnpU\Guard\Exception\CustomAuthenticationException;
use League\OAuth2\Client\Provider\Facebook;
use League\OAuth2\Client\Provider\FacebookUser;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class FacebookAuthenticator extends AbstractGuardAuthenticator
{
    private $em;
    private $appId;
    private $appSecret;
    private $router;

    private $facebookProvider;

    public function __construct(EntityManager $em, $appId, $appSecret, RouterInterface $router)
    {
        $this->em = $em;
        $this->appId = $appId;
        $this->appSecret = $appSecret;
        $this->router = $router;
    }

    public function getCredentials(Request $request)
    {
        if ($request->getPathInfo() != '/connect/facebook-check') {
            // skip authentication unless we're on this URL!
            return null;
        }

        if ($code = $request->query->get('code')) {
            return $code;
        }

        // no code! Something went wrong
        // you could read the error, error_code, error_description, error_reason query params
        // http://localhost:8000/connect/facebook-check?error=access_denied&error_code=200&error_description=Permissions+error&error_reason=user_denied&state=S2fKgHJSZSJM0Qs2fhKL6USZP50KSBHc#_=_
        throw CustomAuthenticationException::createWithSafeMessage(
            'There was an error getting access from Facebook. Please try again.'
        );
    }

    public function getUser($authorizationCode, UserProviderInterface $userProvider)
    {
        // the credentials are really the access token
        $accessToken = $this->getFacebookOAuthProvider()->getAccessToken(
            'authorization_code',
            ['code' => $authorizationCode]
        );

        if (!$accessToken) {
            throw CustomAuthenticationException::createWithSafeMessage(
                'There was an error getting access from Facebook. Please try again.'
            );
        }

        /** @var FacebookUser $userDetails */
        $userDetails = $this->getFacebookOAuthProvider()->getUser($accessToken);

        $email = $userDetails->getEmail();

        // todo - create a user if one doesn't exist
        return $this->em->getRepository('AppBundle:User')
            ->findOneBy(array('email' => $email));
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        // do nothing - if we got a user, we're good
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        // this would happen if something went wrong in the OAuth flow
        $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);

        return new RedirectResponse($this->router->generate('security_login'));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        // todo - remove needing this crazy thing
        $targetPath = $request->getSession()->get('_security.'.$providerKey.'.target_path');

        if (!$targetPath) {
            $targetPath = $this->router->generate('homepage');
        }

        return new RedirectResponse($targetPath);
    }

    public function supportsRememberMe()
    {
        return true;
    }

    /**
     * Starts the authentication scheme.
     *
     * @param Request $request The request that resulted in an AuthenticationException
     * @param AuthenticationException $authException The exception that started the authentication process
     *
     * @return Response
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $authUrl = $this->getFacebookOAuthProvider()->getAuthorizationUrl([
            // these are actually the default copes
            'scopes' => ['public_profile', 'email'],
        ]);

        return new RedirectResponse($authUrl);
    }

    /**
     * @return Facebook
     */
    private function getFacebookOAuthProvider()
    {
        if ($this->facebookProvider === null) {
            $this->facebookProvider = new Facebook(array(
                'clientId' => $this->appId,
                'clientSecret' => $this->appSecret,
                'redirectUri' => $this->router->generate(
                    'connect_facebook_check',
                    [],
                    RouterInterface::ABSOLUTE_URL
                ),
                'graphApiVersion' => 'v2.3',
            ));
        }

        return $this->facebookProvider;
    }
}
