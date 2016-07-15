<?php

use Krak\Mw\JwtAuth,
    Eloquent\Phony as p;

describe('Krak Mw Jwt Auth', function() {
    describe('Validate', function() {
        beforeEach(function() {
            $this->jws = (new Jose\Object\JWS());
        });

        describe('#validateNbf', function() {
            beforeEach(function() {
                $this->validate = JwtAuth\validateNbf();
            });
            it('passes validation if no nbf claim', function() {
                $res = call_user_func($this->validate, [$this->jws, 0]);
                assert($res === null);
            });
            it('validates the nbf claim', function() {
                $jws = $this->jws->withPayload([
                    'nbf' => time() + 20,
                ]);
                $res = call_user_func($this->validate, [$jws, 0]);
                assert($res[0] === 'premature_token');
            });
        });
        describe('#validateExp', function() {
            beforeEach(function() {
                $this->validate = JwtAuth\validateExp();
            });
            it('passes validation if no exp claim', function() {
                $res = call_user_func($this->validate, [$this->jws, 0]);
                assert($res === null);
            });
            it('validates the exp claim', function() {
                $jws = $this->jws->withPayload([
                    'exp' => time() - 20,
                ]);
                $res = call_user_func($this->validate, [$jws, 0]);
                assert($res[0] === 'expired_token');
            });
        });
        describe('#validateChain', function() {
            it('chains validators together', function() {
                $was_called = 0;
                $v = JwtAuth\validateChain([
                    function() use (&$was_called) {$was_called++;},
                    function() { return ['code', 'message'];}
                ]);
                $res = $v([]);

                assert($was_called === 1 && $res[0] == 'code');
            });
        });
        describe('#validateJwt', function() {
            it('is a default validator for Jwt vals', function() {
                $validate = JwtAuth\validateJwt(function() {
                    return ['code'];
                });

                $res = $validate([$this->jws, 0]);
                assert($res[0] === 'code');
            });
        });
        describe('#jwtAuthMw', function() {
            it('validates jwt header', function() {
                $verifier = p\mock('Jose\VerifierInterface');
                $jwk_set = p\mock('Jose\Object\JWKSetInterface');
                $loader = p\mock('Jose\LoaderInterface');
                $loader->load->returns(p\mock('Jose\Object\JWSInterface')->get());
                $mw = JwtAuth\jwtAuthMw($jwk_set->get(), $verifier->get(), function($tup) {
                    return false;
                }, null, $loader->get());

                $req = Zend\Diactoros\ServerRequestFactory::fromGlobals();
                $req = $req->withHeader('Authorization', 'Bearer content');

                $res = $mw($req, function() {
                    return true;
                });

                assert($res);
            });
        });
    });
});
