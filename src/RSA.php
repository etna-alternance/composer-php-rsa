<?php

namespace ETNA\RSA;

class RSA
{
    private $private = null;
    private $public  = null;

    /**
     * @param mixed $key can be one of the following:
     *  - a string having the format file://path/to/file.pem. The named file must contain a PEM encoded private key.
     *  - A PEM formatted private key.
     * @param string $password if the key is password protected
     * @return RSA
     */
    public static function loadPrivateKey($key, $password = "")
    {
        $private_key = openssl_pkey_get_private($key, $password);
        if (false === $private_key) {
            throw new \Exception("Bad Private Key");
        }

        $public_key = openssl_pkey_get_public(openssl_pkey_get_details($private_key)["key"]);
        if (false === $public_key) {
            throw new \Exception("Error getting Public Key");
        }

        return new self($public_key, $private_key);
    }

    /**
     * @param mixed $key can be one of the following:
     *  - a string having the format file://path/to/file.pem. The named file must contain a PEM encoded public key.
     *  - A PEM formatted public key.
     * @return RSA
     */
    public static function loadPublicKey($key)
    {
        $public_key = openssl_pkey_get_public($key);
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

        if (false === @openssl_sign($data, $signature, $this->private)) {
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
