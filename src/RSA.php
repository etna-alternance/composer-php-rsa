<?php

namespace ETNA\RSA;

class RSA
{
    private $private = null;
    private $public  = null;

    /**
     * @param string $path to the private key
     * @param string $password if the key is password protected
     * @return RSA
     */
    public static function loadPrivateKey($path, $password = "")
    {
        $file = realpath($path);
        if (false === $file) {
            throw new \Exception("Private Key not found");
        }

        $private_key = openssl_pkey_get_private("file://{$file}", $password);
        if (false === $private_key) {
            throw new \Exception("Bad Private Key");
        }

        $public_key = openssl_pkey_get_public(openssl_pkey_get_details($private_key)["key"]);
        if (false === $public_key) {
            throw new \Exception("Bad Public Key");
        }

        return new self($public_key, $private_key);
    }

    /**
     * @param string $path to the public key
     * @return RSA
     */
    public static function loadPublicKey($path)
    {
        $file = realpath($path);
        if (false === $file) {
            throw new \Exception("Public Key not found");
        }

        $public_key = openssl_pkey_get_public("file://{$file}");
        if (false === $public_key) {
            throw new \Exception("Bad Public Key");
        }

        return new self($public_key);
    }

    protected function __construct($public, $private = null)
    {
        $this->public  = $public;
        $this->private = $private;
    }

    public function __destruct()
    {
        if (null !== $this->private) {
            openssl_free_key($this->private);
        }
        openssl_free_key($this->public);
    }

    /**
     * @return string
     */
    public function getPublicKey()
    {
        return openssl_pkey_get_details($this->public)["key"];
    }

    /**
     * Signs some $data
     *
     * @param string $data
     * @return string base64encoded signature
     */
    public function sign($data)
    {
        if (null === $this->private) {
            throw new \Exception("Undefined Private Key");
        }

        if (false === openssl_sign($data, $signature, $this->private)) {
            throw new \Exception("Undefined openssl error");
        }

        return base64_encode($signature);
    }

    /**
     * Check Signature
     *
     * @param string $data
     * @param string $signature base64encoded
     * @return boolean true if signature matches
     */
    public function verify($data, $signature)
    {
        return openssl_verify($data, base64_decode($signature), $this->public) == 1;
    }
}
