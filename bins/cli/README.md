# Platform Validator CLI

CLI pour gérer les dynamic values et installer des challenges dans le platform validator.

## Installation

```bash
cargo build --release --bin pv
```

Le binaire sera disponible dans `target/release/pv`.

## Commandes

### Dynamic Values

Gérer les dynamic values d'un challenge.

#### Set
Définir une dynamic value pour un challenge:

```bash
pv dynamic set --challenge-id website-challenge --key resources.cpu_cores --value 8
```

#### Get
Récupérer une dynamic value:

```bash
pv dynamic get --challenge-id website-challenge --key resources.cpu_cores
```

#### List
Lister toutes les dynamic values d'un challenge:

```bash
pv dynamic list --challenge-id website-challenge
```

#### Delete
Supprimer une dynamic value:

```bash
pv dynamic delete --challenge-id website-challenge --key resources.cpu_cores
```

### Challenge Installation

#### Install
Installer un challenge depuis un dépôt Git:

```bash
pv challenge install --repo-url https://github.com/user/challenge-repo.git --ref-name main
```

Options:
- `--repo-url`: URL du dépôt Git
- `--ref-name`: Branch ou commit hash (défaut: main)
- `--install-dir`: Dossier d'installation (défaut: ./challenges)
- `--validator-url`: URL du validator (défaut: http://localhost:3030)

Le CLI va:
1. Cloner le dépôt
2. Checkouter le commit spécifié
3. Charger et afficher le `platform.json`
4. Si `interactiveInstallation` est présent, demander les valeurs requises
5. Copier le challenge dans le dossier d'installation

#### Validate
Valider une installation de challenge:

```bash
pv challenge validate --challenge-dir ./challenges/website-challenge
```

## Interactive Installation

Le CLI supporte l'installation interactive de challenges qui requièrent des valeurs de configuration spécifiques au validateur.

### Configuration dans platform.json

```json
{
  "interactive_installation": {
    "required_validator_values": [
      {
        "key": "resources.cpu_cores",
        "description": "Number of CPU cores available",
        "default_value": 4,
        "validation": {
          "type": "number",
          "min": 1,
          "max": 16
        }
      }
    ]
  }
}
```

### Types de validation

- **number**: Valeur numérique avec optionnellement `min` et `max`
- **string**: Chaîne de caractères avec optionnellement un `pattern` regex
- **boolean**: Valeur booléenne (true/false)

## Exemples

### Installation complète d'un challenge

```bash
# Cloner et installer avec configuration interactive
pv challenge install --repo-url https://github.com/user/challenge.git

# Le CLI va demander les valeurs requises si interactiveInstallation est défini
# Puis il télécharge le challenge et configure les dynamic values
```

### Modifier manuellement les ressources

```bash
# Voir les valeurs actuelles
pv dynamic list --challenge-id website-challenge

# Modifier le nombre de CPU
pv dynamic set --challenge-id website-challenge --key resources.cpu_cores --value 8

# Modifier la mémoire
pv dynamic set --challenge-id website-challenge --key resources.memory_mb --value 16384
```

## Intégration avec le Validator

Le CLI communique avec le serveur HTTP du validator (port 3030 par défaut). Assurez-vous que le validator est démarré avant d'utiliser le CLI.

## Sécurité

Les dynamic values validator sont stockées localement dans une base SQLite et ne peuvent être modifiées que via le CLI ou l'API HTTP du validator. Les dynamic values globales restent contrôlées par l'API de la plateforme.
