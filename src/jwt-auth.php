<?php

namespace Krak\Mw\JwtAuth;

use Psr\Http\Message\ServerRequestInterface,
    Krak\HttpMessage,
    Jose\Checker,
    Jose\LoaderInterface,
    Jose\Loader,
    Jose\VerifierInterface,
    Jose\Object\JWKSetInterface,
    Jose\Object\JWSInterface;

function validateExp() {
    return function($jwt_tup) {
        list($jwt, $sig_index) = $jwt_tup;

        if (!$jwt->hasClaim('exp')) {
            return;
        }

        if ($jwt->getClaim('exp') >= time()) {
            return;
        }

        return ['expired_token', 'The token has been expired'];
    };
}

function validateNbf() {
    return function($jwt_tup) {
        list($jwt, $sig_index) = $jwt_tup;

        if (!$jwt->hasClaim('nbf')) {
            return;
        }

        if ($jwt->getClaim('nbf') < time()) {
            return;
        }

        return ['premature_token', 'The token is not valid yet'];
    };
}

function validateChain($validators) {
    return function($jwt_tup) use ($validators) {
        foreach ($validators as $v) {
            $res = $v($jwt_tup);
            if ($res) {
                return $res;
            }
        }
    };
}

function validateJwt($validate = null) {
    return validateChain(array_filter([
        validateExp(),
        validateNbf(),
        $validate
    ]));
}

function jwtAuthMwFactory(
    JWKSetInterface $jwk_set,
    VerifierInterface $verifier,
    $validate = null,
    LoaderInterface $loader = null,
    $token_attribute_name = 'jwt'
) {
    return function($resp_factory) use ($jwk_set, $verifier, $validate, $loader, $token_attribute_name) {
        return jwtAuthMw($jwk_set, $verifier, $resp_factory, $validate, $loader, $token_attribute_name);
    };
}

function jwtAuthMw(
    JWKSetInterface $jwk_set,
    VerifierInterface $verifier,
    $resp_factory,
    $validate = null,
    LoaderInterface $loader = null,
    $token_attribute_name = 'jwt'
) {
    $validate = $validate ?: validateJwt();
    $loader = $loader ?: new Loader();
    return function(ServerRequestInterface $req, $next) use ($jwk_set, $verifier, $resp_factory, $validate, $loader, $token_attribute_name) {
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
            return $resp_factory(['invalid_signature', 'Invalid Token Signature']);
        }

        $err = $validate([$jwt, $signature_index]);
        if ($err) {
            return $resp_factory($err);
        }

        // jwt is validated, let's populate the request with it and pass along
        return $next($req->withAttribute($token_attribute_name, $jwt));
    };
}
