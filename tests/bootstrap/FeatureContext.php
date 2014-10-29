<?php

use Behat\Behat\Context\Context;
use ETNA\RSA\RSA;

/**
 * Features context.
 */
class FeatureContext implements Context
{
    private $identity;
    private $context;
    private $rsa;
    private $public_path;
    private $private_path;
    private $exception;
    private $sign;

    /**
     * @BeforeSuite
     */
    public static function setUpEverything()
    {
        if (false === file_exists("tmp/keys")) {
            mkdir("tmp/keys", 0777, true);
        }

        if (false === file_exists("tmp/keys/private.key")) {
            self::safeExec(
                "openssl genrsa  -out tmp/keys/private.key 2048",
                "Erreur lors de la génération de la clef privée"
            );
        }

        if (false === file_exists("tmp/keys/public.key")) {
            self::safeExec(
                "openssl rsa -in tmp/keys/private.key -pubout -out tmp/keys/public.key",
                "Erreur lors de la génération de la clef publique"
            );
        }

        file_put_contents("tmp/keys/blu.txt", "blu");
    }

    /**
     * @param string $command
     * @param string $error_message
     */
    private static function safeExec($command, $error_message)
    {
        $return_var = null;
        system($command, $return_var);
        if (0 !== $return_var) {
            throw \Exception($error_message);
        }
    }

    /**
    * @AfterScenario
    **/
    public function laCleDevraitEtreLibere()
    {
        if (true === isset($this->context) && $this->context === "volontairement fausse") {
            $this->mockMethod('ETNA\RSA\RSA', '__destruct');
        }

        if (true === isset($this->rsa) && $this->rsa instanceof RSA) {
            $this->rsa->__destruct();
        }
    }

    /**
     * @Given /^que cette clé public est (valide|invalide|inexistante)$/
     */
    public function queCetteClePublicEstValide()
    {
        try {
            $this->rsa = RSA::loadPublicKey($this->public_path);
        } catch (Exception $e) {
            $this->exception = $e->getMessage();
        }
    }

    /**
     * @Given /^que cette clé privée est (valide|invalide|inexistante|volontairement fausse)$/
     */
    public function queCetteClePriveeEstValide($context)
    {
        if ($context === "volontairement fausse") {
            $this->context = $context;
            $this->mockMethod(
                'ETNA\RSA\RSA',
                '__construct',
                '$public, $private=null',
                '$this->public = $public; $this->private = $private;'
            );

            $this->rsa = new RSA("blu", "blu");
            return;
        }
        try {
            $this->rsa = RSA::loadPrivateKey($this->private_path);
        } catch (Exception $e) {
            $this->exception = $e->getMessage();
        }
    }

     /**
     * @Given /^je devrais obtenir un objet RSA$/
     */
    public function jeDevraisObtenirUnObjetRsa()
    {
        if (false === $this->rsa instanceof RSA) {
            throw new Exception("Not a RSA object");
        }
    }

    /**
     * @Given /^sa clé public devrait ressembler à "([^"]*)"$/
     */
    public function saClePublicDevraitRessemblerA($public_path)
    {
        return $this->rsa->getPublicKey() === file_get_contents($this->getAbsolutePath($public_path));
    }

    /**
     * @Given /^que ma clé privée se trouve dans "([^"]*)"$/
     */
    public function queMaClePriveeSeTrouveDans($private_path)
    {
        $this->private_path = $this->getAbsolutePath($private_path);
    }

    /**
     * @Given /^que ma clé public se trouve dans "([^"]*)"$/
     */
    public function queMaClePublicSeTrouveDans($public_path)
    {
        $this->public_path = $this->getAbsolutePath($public_path);
    }

    /**
     * @Given /^je devrais obtenir une exception "([^"]*)"$/
     */
    public function jeDevraisObtenirUneException($message)
    {
        if ($this->exception !== $message) {
            throw new Exception("Incorrect Exception got:'{$this->exception}', expected:'{$message}'");
        }
    }

    /**
     *@Given /^je m\'authentifie en tant que "([^"]*)"(?: depuis (\d+) minutes?)?(?: avec les roles "([^"]*)")?(?: avec l'id (\d+))?/
     */
    public function jeMAuthentifieEn($login, $duration = 1, $roles = "", $id = 1)
    {
        $duration = (int) $duration;
        $id       = (int) $id;

        $this->identity = base64_encode(
            json_encode(
                [
                    "id"         => $id,
                    "login"      => $login,
                    "logas"      => false,
                    "groups"     => explode(",", $roles),
                    "login_date" => date("Y-m-d H:i:s", strtotime("now -{$duration}minutes")),
                ]
            )
        );

        if (true === isset($this->context) && $this->context === "volontairement fausse") {
            error_reporting(E_DEPRECATED);
        }

        try {
            $this->sign = $this->rsa->sign($this->identity);
        } catch (Exception $e) {
            $this->exception = $e->getMessage();
        }
    }

    /**
     * @Given /^je dois pouvoir vérifier mon authentification(?: avec la clé public "([^"]*)")?$/
     */
    public function jeDoisPouvoirLaVerifier($public_path=null)
    {
        if ($public_path !== null) {
            $this->rsa = RSA::loadPublicKey($this->getAbsolutePath($public_path));
        }
        if (false === $this->rsa->verify($this->identity, $this->sign)) {
            throw new Exception("L'identité n'a pas pu être vérifiée");
        }
    }

    public function getAbsolutePath($relative_path)
    {
        return __DIR__ . "/../../" . $relative_path;
    }

    /**
     * @param string $classname
     * @param string $methodname
     */
    public function mockMethod($classname, $methodname, $args='', $code='', $flags=RUNKIT_ACC_PUBLIC)
    {
        runkit_method_redefine($classname, $methodname, $args, $code, $flags);
    }
}
