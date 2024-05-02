<?php

namespace Ispahbod\CookieManager;

class CookieManager
{
    protected $encryptionKey;
    protected $defaultExpiry = 3600; 
    protected $defaultSecure = true; 
    protected $defaultHttpOnly = true; 

    public function __construct($encryptionKey = 'default_secret_key')
    {
        $this->encryptionKey = $encryptionKey;
    }

    public function setCookie($name, $value, $expiry = null, $path = '/', $domain = '', $secure = null, $httpOnly = null)
    {
        $expiry = $expiry ?? $this->defaultExpiry;
        $secure = $secure ?? $this->defaultSecure;
        $httpOnly = $httpOnly ?? $this->defaultHttpOnly;

        $encryptedValue = openssl_encrypt($value, 'AES-256-CBC', $this->encryptionKey, 0, substr($this->encryptionKey, 0, 16));
        setcookie($name, $encryptedValue, time() + $expiry, $path, $domain, $secure, $httpOnly);
    }

    public function getCookie($name)
    {
        if (isset($_COOKIE[$name])) {
            $decryptedValue = openssl_decrypt($_COOKIE[$name], 'AES-256-CBC', $this->encryptionKey, 0, substr($this->encryptionKey, 0, 16));
            return $decryptedValue;
        }
        return null;
    }

    public function deleteCookie($name, $path = '/', $domain = '')
    {
        setcookie($name, '', time() - 3600, $path, $domain);
        unset($_COOKIE[$name]);
    }

    public function hasCookie($name)
    {
        return isset($_COOKIE[$name]);
    }

    public function updateCookie($name, $value, $expiry = null, $path = '/', $domain = '', $secure = null, $httpOnly = null)
    {
        $this->setCookie($name, $value, $expiry, $path, $domain, $secure, $httpOnly);
    }

    public function listCookies()
    {
        return array_keys($_COOKIE);
    }

    public function clearAllCookies($path = '/', $domain = '')
    {
        foreach ($_COOKIE as $name => $value) {
            $this->deleteCookie($name, $path, $domain);
        }
    }
}