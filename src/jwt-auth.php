<?php

namespace Krak\Mw\JwtAuth;

use Psr\Http\Message\ServerRequestInterface,
    Krak\HttpMessage,
    Jose\Checker\CheckerManagerInterface,
    Jose\LoaderInterface,
    Jose\Loader,
    Jose\VerifierInterface,
    Jose\Object\JWKSetInterface,
    Jose\Object\JWSInterface;

function jwtAuthMwFactory(
    JWKSetInterface $jwk_set,
    VerifierInterface $verifier,
    CheckerManagerInterface $checker,
    LoaderInterface $loader = null,
    $token_attribute_name = 'jwt'
) {
    return function($resp_factory) use ($jwk_set, $verifier, $checker, $loader, $token_attribute_name) {
        return jwtAuthMw($jwk_set, $verifier, $checker, $resp_factory, $loader, $token_attribute_name);
    };
}

function jwtAuthMw(
    JWKSetInterface $jwk_set,
    VerifierInterface $verifier,
    CheckerManagerInterface $checker,
    $resp_factory,
    LoaderInterface $loader = null,
    $token_attribute_name = 'jwt'
) {
    $loader = $loader ?: new Loader();
    return function(ServerRequestInterface $req, $next) use ($jwk_set, $checker, $verifier, $resp_factory, $loader, $token_attribute_name) {
        $auth_header = HttpMessage\AuthorizationHeader::fromHttpMessage($req);

        if (!$auth_header) {
            return $resp_factory(['invalid_auth_header', 'Invalid Authorization header']);
        }

        if ($auth_header->scheme != 'Bearer') {
            return $resp_factory(['invalid_auth_scheme', 'Expected "Bearer" authorization scheme']);
        }

        try {
            $jwt = $loader->load($auth_header->credentials);
        } catch (\Exception $e) {
            return $resp_factory(['invalid_token', 'Invalid Token Format']);
        }

        if (!$jwt instanceof JWSInterface) {
            return $resp_factory(['invalid_token', 'Invalid Token Format']);
        }

        try {
            $verifier->verifyWithKeySet($jwt, $jwk_set, null, $signature_index);
        } catch (\Exception $e) {
            return $resp_factory(['failed_verification', 'Failed Token Verification']);
        }

        try {
            $checker->checkJWS($jwt, $signature_index);
        } catch (\Exception $e) {
            return $resp_factory(['failed_validation', 'Failed Token Validation']);
        }

        // jwt is validated, let's populate the request with it and pass along
        return $next($req->withAttribute($token_attribute_name, $jwt));
    };
}
