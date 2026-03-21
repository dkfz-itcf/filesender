<?php
/**
 * FileSender www.filesender.org
 *
 * Copyright (c) 2009-2014, AARNet, Belnet, HEAnet, SURF, UNINETT
 * All rights reserved.
 */

if (!defined('FILESENDER_BASE')) {
    die('Missing environment');
}


class AuthOAuth2Token
{
    private static $isAuthenticated = null;
    private static $tokenAttributes = null;
    private static $validatedToken = null;

    public static function isAuthenticated(): bool
    {
        if (is_null(self::$isAuthenticated)) {
            self::$isAuthenticated = false;

            if (!Config::get('auth_oauth2_token_enabled')) {
                return false;
            }

            $token = self::getAccessTokenFromRequest();
            if (!$token) {
                return false;
            }

            try {
                self::$validatedToken = self::validateToken($token);
                self::$tokenAttributes = self::extractTokenAttributes(self::$validatedToken);
                self::$isAuthenticated = true;
            } catch (AuthOAuth2TokenValidationException $e) {
                self::$isAuthenticated = false;
                throw $e;
            }
        }
        return self::$isAuthenticated;
    }

    public static function getAccessTokenFromRequest()
    {
        if (array_key_exists('Authorization', $_SERVER)) {
            $authHeader = $_SERVER['Authorization'];
            if (preg_match('/Bearer\s+(\S+)/', $authHeader, $matches)) {
                return $matches[1];
            }
        }

        if (array_key_exists('access_token', $_GET)) {
            return $_GET['access_token'];
        }

        $customHeader = Config::get('auth_oauth2_token_header');
        if ($customHeader && array_key_exists($customHeader, $_SERVER)) {
            return $_SERVER[$customHeader];
        }

        return null;
    }

    public static function validateToken($token)
    {
        $tokenFormat = Config::get('auth_oauth2_token_format');

        if ($tokenFormat === 'jwt') {
            return self::validateJwtToken($token);
        } else {
            return self::validateOpaqueToken($token);
        }
    }

    private static function validateJwtToken($token)
    {
        $parts = explode('.', $token);
        if (count($parts) === 3) {
            list($headerEncoded, $payloadEncoded, $signatureEncoded) = $parts;

            $header = json_decode(base64_decode($headerEncoded), true);
            $payload = json_decode(base64_decode($payloadEncoded), true);

            if (!is_array($header) || !is_array($payload)) {
                throw new AuthOAuth2TokenValidationException('Invalid JWT structure');
            }

            $expectedIssuer = Config::get('auth_oauth2_idp_issuer');
            if ($expectedIssuer && isset($payload['iss']) && $payload['iss'] !== $expectedIssuer) {
                throw new AuthOAuth2TokenIssuerMismatchException($payload['iss'], $expectedIssuer);
            }

            if (isset($payload['exp']) && $payload['exp'] < time()) {
                throw new AuthOAuth2TokenExpiredException($payload['exp']);
            }

            $publicKey = Config::get('auth_oauth2_token_public_key');
            if ($publicKey) {
                $signed = $headerEncoded . '.' . $payloadEncoded;
                $signature = hash_hmac('sha256', $signed, $publicKey);

                if ($signature !== $signatureEncoded) {
                    throw new AuthOAuth2TokenSignatureValidationException($signature, $signatureEncoded);
                }
            }

            return $payload;
        }

        throw new AuthOAuth2TokenValidationException('Unsupported JWT format');
    }

    private static function validateOpaqueToken($token)
    {
        $introspectionEndpoint = Config::get('auth_oauth2_token_introspection_endpoint');

        if ($introspectionEndpoint) {
            $introspection = self::callTokenIntrospection($token, $introspectionEndpoint);

            if (!isset($introspection['active']) || $introspection['active'] !== true) {
                throw new AuthOAuth2TokenIntrospectionFailedException($token);
            }

            if (isset($introspection['exp']) && $introspection['exp'] < time()) {
                throw new AuthOAuth2TokenExpiredException($introspection['exp']);
            }

            return $introspection;
        }

        throw new AuthOAuth2TokenValidationException('No introspection endpoint configured');
    }

    public static function callTokenIntrospection($token, $endpoint)
    {
        $ch = curl_init($endpoint);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(array('token' => $token)));

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200 || $response === false) {
            throw new AuthOAuth2TokenIntrospectionConnectionException($endpoint, $httpCode);
        }

        return json_decode($response, true);
    }

    public static function extractTokenAttributes($validatedToken)
    {
        $attributes = array();

        if (isset($validatedToken['sub'])) {
            $attributes['uid'] = $validatedToken['sub'];
        }

        if (isset($validatedToken['email'])) {
            $attributes['email'] = is_array($validatedToken['email']) ? $validatedToken['email'] : array($validatedToken['email']);
        }

        if (isset($validatedToken['name'])) {
            $attributes['name'] = $validatedToken['name'];
        }

        if (isset($validatedToken['iss'])) {
            $attributes['idp'] = $validatedToken['iss'];
        }

        $additionalAttributes = Config::get('auth_oauth2_token_attributes');
        if ($additionalAttributes) {
            $attributes['additional'] = array();
            foreach ($additionalAttributes as $key => $claim) {
                if (isset($validatedToken[$claim])) {
                    $attributes['additional'][$key] = $validatedToken[$claim];
                }
            }
        }

        return $attributes;
    }

    public static function attributes(): array
    {
        if (!self::isAuthenticated()) {
            throw new AuthAuthenticationNotFoundException();
        }

        return self::$tokenAttributes;
    }
}