# Sentinelle

**Sentinelle** est une application desktop Windows qui surveille les processus et aide à contrôler les programmes exécutés sur votre ordinateur. Elle conserve un historique des programmes détectés, même après leur fermeture.

## Fonctionnalités

*   **Surveillance des processus** : détection en arrière-plan toutes les 0,9 seconde et actualisation visuelle toutes les 15 secondes.
*   **Historique persistant** : les programmes détectés restent consultables après leur arrêt et après le redémarrage de l'application.
*   **Filtres et recherche** : affichez tous les programmes, les programmes bloqués ou autorisés ; recherchez par nom et triez les colonnes.
*   **Blocage réactif** : choisissez un programme à bloquer ou autoriser ; vos choix sont mémorisés entre les sessions.
*   **Pare-feu Windows** : configurez séparément les règles entrantes et sortantes pour un exécutable, après confirmation administrateur.
*   **Zone de notification** : fermer la fenêtre masque l'application sans interrompre la surveillance.
*   **Démarrage automatique** : lancez Sentinelle avec Windows, sans fenêtre de terminal.
*   **Interface personnalisée** : thème sombre, icône dédiée et bouton de don.

## Installation

### Prérequis
*   Windows 10 ou 11
*   Python 3.11 ou plus récent

### Configuration
1.  Installez les dépendances depuis ce dossier :
    ```bash
    py -m pip install -r requirements.txt
    ```

2.  Double-cliquez sur `Sentinelle.bat`.

Le lanceur utilise `pyw.exe` ou `pythonw.exe` pour démarrer l'application sans laisser de terminal ouvert.

## Utilisation

Sélectionnez un programme puis cliquez sur **Bloquer ce programme** ou **Autoriser ce programme**. Pour gérer uniquement ses règles réseau, utilisez le bouton **Configurer le pare-feu** ou **Retirer le blocage réseau**.

Fermer la fenêtre avec la croix réduit Sentinelle dans la zone de notification. Pour arrêter complètement la surveillance, choisissez **Quitter** dans le menu de l'icône.

## Limites

Le blocage des processus est réactif : un programme peut démarrer brièvement avant d'être détecté et arrêté. Ce mécanisme ne garantit pas une interdiction de lancement à 100 %. Les règles du Pare-feu Windows s'appliquent au chemin exact de l'exécutable et nécessitent que le pare-feu soit actif. Une interdiction de lancement imposée par Windows nécessite une stratégie AppLocker ou Windows Defender Application Control configurée avec précaution.

## Technologies

*   **Python** / **Tkinter** pour l'interface desktop
*   **psutil** pour détecter et interroger les processus
*   **pystray** pour l'icône et le menu de la zone de notification
*   **Pillow** pour le traitement de l'icône
*   **Pare-feu Windows** pour les règles réseau entrantes et sortantes

## Licence

Ce projet est distribué sous licence **GNU AGPL-3.0**, comme Windows Manager. Voir le fichier [`LICENSE`](LICENSE) pour le texte intégral.

---
*Codé 100 % par des IA, supervisé à l'arrache par Obat 😏*
