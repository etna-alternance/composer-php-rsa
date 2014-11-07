# language: fr

@feature/rsa/rsa
Fonctionnalité: Je manipule des clés privées

Plan du Scénario: Je lis une clé public ou privée
    Etant donné que ma clé <domaine> se trouve dans <keypath>
    Et que cette clé <domaine> est valide
    Alors je devrais obtenir un objet RSA
    Et sa clé public devrait ressembler à "tmp/keys/public.key"
    Exemples:
        | domaine | keypath                |
        | privée  | "tmp/keys/private.key" |
        | public  | "tmp/keys/public.key"  |

Plan du Scénario: Je lis une clé privée ou public qui n'existe pas
    Etant donné que ma clé <domaine> se trouve dans "tmp/toto.txt"
    Et que cette clé <domaine> est invalide
    Alors je devrais obtenir une exception <exception>
    Exemples:
        | domaine | exception         |
        | privée  | "Bad Private Key" |
        | public  | "Bad Public Key"  |

Plan du Scénario: Je lis une clé privée ou public invalide
    Etant donné que ma clé <domaine> se trouve dans "tmp/keys/blu.txt"
    Et que cette clé <domaine> est invalide
    Alors je devrais obtenir une exception <exception>
    Exemples:
        | domaine | exception         |
        | privée  | "Bad Private Key" |
        | public  | "Bad Public Key"  |

Scénario: Je signe une donnée sans private.key
    Etant donné que ma clé public se trouve dans "tmp/keys/public.key"
    Et que cette clé public est valide
    Quand je m'authentifie en tant que "student_1"
    Alors je devrais obtenir une exception "Undefined Private Key"

Scénario: Je signe une donnée et je la verifie grâce à ma clé privé
    Etant donné que ma clé privée se trouve dans "tmp/keys/private.key"
    Et que cette clé privée est valide
    Quand je m'authentifie en tant que "student_1"
    Alors je dois pouvoir vérifier mon authentification

Scénario: Je signe une donnée et je la verifie grâce à ma clé public
    Etant donné que ma clé privée se trouve dans "tmp/keys/private.key"
    Et que cette clé privée est valide
    Quand je m'authentifie en tant que "student_1"
    Alors je dois pouvoir vérifier mon authentification avec la clé public "tmp/keys/public.key"

Scénario: Je signe une donnée et je la verifie grâce à ma clé privée
    Etant donné que ma clé privée se trouve dans "tmp/keys/private.key"
    Et que cette clé privée est volontairement fausse
    Quand je m'authentifie en tant que "student_1"
    Alors je devrais obtenir une exception "Undefined openssl error"
