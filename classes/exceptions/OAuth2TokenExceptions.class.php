<?php

if (!defined('FILESENDER_BASE')) {
    die('Missing environment');
}

class AuthOAuth2TokenValidationException extends DetailedException
{
    public function __construct($reason = null)
    {
        parent::__construct(
            'auth_oauth2_token_validation_failed',
            array('reason' => $reason)
        );
    }
}

class AuthOAuth2TokenExpiredException extends DetailedException
{
    public function __construct($expTime)
    {
        parent::__construct(
            'auth_oauth2_token_expired',
            array('exp' => $expTime)
        );
    }
}

class AuthOAuth2TokenIssuerMismatchException extends DetailedException
{
    public function __construct($tokenIssuer, $expectedIssuer)
    {
        parent::__construct(
            'auth_oauth2_token_issuer_mismatch',
            array('token_issuer' => $tokenIssuer, 'expected_issuer' => $expectedIssuer)
        );
    }
}

class AuthOAuth2TokenSignatureValidationException extends DetailedException
{
    public function __construct($computedSignature, $tokenSignature)
    {
        parent::__construct(
            'auth_oauth2_token_signature_mismatch',
            array('computed' => $computedSignature, 'token' => $tokenSignature)
        );
    }
}

class AuthOAuth2TokenIntrospectionFailedException extends DetailedException
{
    public function __construct($token)
    {
        parent::__construct(
            'auth_oauth2_token_introspection_failed',
            array('token' => $token)
        );
    }
}

class AuthOAuth2TokenIntrospectionConnectionException extends DetailedException
{
    public function __construct($endpoint, $httpCode)
    {
        parent::__construct(
            'auth_oauth2_token_introspection_connection_failed',
            array('endpoint' => $endpoint, 'http_code' => $httpCode)
        );
    }
}