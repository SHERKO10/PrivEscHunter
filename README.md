# PrivEscHunter

Analyseur PowerShell des vecteurs d'élévation de privilèges sous Windows.

PrivEscHunter collecte des informations locales, recherche des configurations potentiellement dangereuses et affiche un rapport de sécurité directement dans la console. Chaque résultat est classé par niveau de sévérité et, lorsque cela est pertinent, associé à une technique MITRE ATT&CK, des éléments de preuve et une recommandation de remédiation.

## Fonctionnalités

- Informations sur le système, la version de Windows, les correctifs et le mode de langage PowerShell
- Analyse de l'identité courante, des groupes et des privilèges actifs
- Énumération des utilisateurs locaux
- Recherche de services exécutés avec des privilèges élevés et de configurations faibles
- Vérification de clés et configurations du registre
- Analyse des tâches planifiées
- Énumération réseau locale
- Vérification de permissions faibles sur certains fichiers et répertoires
- Score de risque global et résultats classés `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` ou `INFO`
- Affichage coloré, avec option de sortie sans couleur pour enregistrer le rapport

## Prérequis

- Windows 10 ou Windows 11, ou Windows Server compatible
- Windows PowerShell 5.1 minimum ou PowerShell 7+
- Une console PowerShell
- Des droits administrateur peuvent être nécessaires pour obtenir une visibilité complète sur certaines informations

Le script utilise principalement des commandes natives Windows et ne nécessite pas de module externe.

## Utilisation

Ouvrir PowerShell dans le dossier du projet, puis exécuter :

```powershell
.\PrivEscHunter.ps1
```

### Options

```text
-SkipNetworkEnum  Ignore l'énumération réseau pour réduire la durée et le bruit
-NoColor          Désactive les couleurs de la console, utile pour une redirection vers un fichier
-Verbose          Active les messages détaillés de PowerShell
```

Exemples :

```powershell
# Analyse complète
.\PrivEscHunter.ps1

# Analyse sans énumération réseau
.\PrivEscHunter.ps1 -SkipNetworkEnum

# Analyse sans couleurs
.\PrivEscHunter.ps1 -NoColor

# Enregistrer la sortie dans un fichier texte lisible
.\PrivEscHunter.ps1 -NoColor > rapport.txt

# Afficher les détails supplémentaires de PowerShell
.\PrivEscHunter.ps1 -Verbose
```

Si PowerShell bloque l'exécution des scripts, vérifier la politique d'exécution appliquée à la session et, si cela est autorisé par l'environnement, lancer :

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\PrivEscHunter.ps1
```

## Comprendre le rapport

Le rapport affiche d'abord un tableau de bord avec un score global et le nombre de résultats par sévérité. Les résultats détaillés indiquent généralement :

- la catégorie et le niveau de sévérité ;
- la description du risque ;
- les éléments de preuve observés ;
- la technique MITRE ATT&CK associée, lorsqu'elle est disponible ;
- des outils ou commandes de vérification ;
- une recommandation de mitigation.

Le score est un indicateur d'aide à l'analyse. Il ne remplace pas une validation manuelle, une analyse de risque complète ou un test d'exploitation contrôlé.

## Cadre d'utilisation

Utiliser uniquement ce script sur des machines que vous possédez ou pour lesquelles vous disposez d'une autorisation explicite. Les informations affichées peuvent contenir des données sensibles sur le système, les comptes, les services ou le réseau. Traiter et stocker les rapports conformément aux règles de sécurité de votre organisation.

PrivEscHunter est un outil d'énumération et d'aide à l'audit. Il ne corrige pas automatiquement les vulnérabilités et ne garantit pas qu'un système est sécurisé lorsqu'aucun résultat n'est détecté.