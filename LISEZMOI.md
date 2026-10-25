# CoffreFort

Gestionnaire de mots de passe local, 100 % hors ligne.

## Lancer
Double-clic sur `Lancer CoffreFort.bat`.

## Sécurité
- Les données sont chiffrées en **AES-256-GCM** avec une clé aléatoire, enfermée dans deux « serrures » :
  le **mot de passe maître** et la **clé de secours**. L'une ou l'autre suffit.
- Chaque serrure est protégée par **Argon2id** (256 Mio, 10 passes) : force brute très coûteuse.
- Toute altération du fichier est détectée. Écriture atomique, copie `.bak`.
- Copie dans le presse-papiers exclue de l'historique Windows (Win+V) et du cloud, effacée après 20 s.
- Verrouillage auto après 5 min d'inactivité ; délai croissant après 3 mauvais essais.
- Aucune connexion réseau.

## Fichier du coffre
`%LOCALAPPDATA%\CoffreFort\coffre.vault` (+ `coffre.vault.bak`)

**Sauvegarde** : copie ce fichier sur une clé USB / un autre disque de temps en temps.
Il est chiffré, donc sans danger tant que le mot de passe maître est solide.

## Mot de passe maître oublié
À la création, CoffreFort affiche une **clé de secours** (`XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`).
Recopie-la sur papier et range-la en lieu sûr, hors du PC.

En cas d'oubli : écran de connexion → « Mot de passe oublié ? » → saisis la clé → choisis un nouveau mot de passe maître.

Bouton **🛟 Clé de secours** : génère une nouvelle clé (l'ancienne cesse de fonctionner), si tu l'as perdue ou si quelqu'un l'a vue.

**Mot de passe maître ET clé de secours perdus = coffre irrécupérable.** Aucune porte dérobée.

## Dépendances
`python -m pip install --user cryptography argon2-cffi`

## Extension navigateur (Brave, Opera GX, Chrome, Edge)
Remplit tes identifiants en un clic, directement depuis CoffreFort.

**Installation (une fois)**
1. Double-clic sur `Installer extension.bat` (déjà fait sur ce PC).
2. Ouvre `brave://extensions` (ou `opera://extensions`, `chrome://extensions`), active le **Mode développeur**.
3. **Charger l'extension non empaquetée** → choisis le dossier `CoffreFort\extension`.
4. Épingle l'icône, ouvre-la → **Associer** → vérifie que le même code s'affiche dans CoffreFort → **Associer**.

**Utilisation**
- Sur une page de connexion : clic sur l'icône → clic sur le compte → c'est rempli.
- Raccourci **Ctrl+Maj+L** : remplit directement s'il n'y a qu'un compte pour le site
  (modifiable dans `brave://extensions/shortcuts`).
- Inscription : « ＋ Nouveau compte sur ce site » → mot de passe fort généré, enregistré et rempli.
- CoffreFort doit être ouvert et déverrouillé (l'extension peut le lancer).

**Pour qu'un compte soit proposé**, renseigne le champ **Adresse** de l'entrée (ex. `accounts.google.com`).
Il n'est proposé que sur ce domaine et ses sous-domaines : un faux site (`google.com.arnaque.ru`) n'obtient rien.

**Sécurité** : l'extension ne stocke aucun mot de passe et ne peut pas lister ton coffre. Elle demande
un seul identifiant, pour le site de l'onglet, à CoffreFort, qui vérifie l'association (stockée dans le coffre chiffré).
Rien ne se remplit tout seul : toujours sur ton clic. Révocation : ⚙ Réglages → Extensions navigateur.
Désinstaller le lien : `python install_extension.py --uninstall`.

## Sauvegarde automatique dans le cloud (MEGA)
À chaque modification (et à chaque déverrouillage), CoffreFort copie le coffre **déjà chiffré** dans
`Documents\MEGA\CoffreFort-Sauvegarde` (réglable : ⚙ Réglages → Sauvegarde automatique) :
- `coffre.vault` : dernière version ;
- `versions\` : une copie par jour, 30 jours ;
- `CoffreFort-programme.zip` : le programme, pour tout réinstaller ;
- `RESTAURER.txt` : la marche à suivre.

MEGA ne voit qu'un fichier chiffré : sans mot de passe maître ni clé de secours, il est illisible.
**Vérifie dans MEGA que `Documents\MEGA` est bien un dossier synchronisé.**

Sur un nouveau PC : voir `RESTAURER.txt` (écran de création → « Restaurer une sauvegarde… »).

## Mises à jour
- **Appli** : si ses fichiers sont mis à jour pendant qu'elle tourne, un bandeau bleu propose
  « Redémarrer maintenant ». Si le coffre est verrouillé et que tu n'es pas au clavier, elle redémarre seule.
- **Extension** : à l'ouverture, elle compare sa version à celle du dossier et se recharge d'elle-même
  (rouvre-la ensuite). Si ça ne suffit pas, elle affiche un bouton vers la page des extensions (↻).

## Partager CoffreFort avec un ami (mise à jour automatique)

Chaque personne a **son propre coffre**, chiffré sur son PC. Seul le programme est partagé, via un dépôt GitHub public.
Il ne contient jamais ton coffre, tes réglages ni ta clé de signature (liste blanche dans `publier.py`).

**Toi, une seule fois :**
1. Crée un compte sur https://github.com, puis un dépôt **Public**, vide (sans README), nommé par exemple `CoffreFort`.
2. Double-clique sur **Publier mise a jour.bat** et colle l'adresse du dépôt. Connecte-toi à GitHub quand la fenêtre s'ouvre.
3. Envoie à ton ami le lien du dépôt : la page explique comment installer (Download ZIP → **Installer CoffreFort.bat**).

**Ensuite, à chaque nouvelle version :** relance **Publier mise a jour.bat**. Le CoffreFort de ton ami l'installe
au lancement suivant, ou dans les 6 heures s'il est déjà ouvert (bandeau de redémarrage).

**Sécurité des mises à jour :** chaque version est signée avec une clé créée sur ton PC
(`%LOCALAPPDATA%\CoffreFort\publication\cle_signature.pem`, copiée dans ton dossier de sauvegarde MEGA).
Sa copie refuse toute version non signée, modifiée, plus ancienne ou qui changerait la clé, même si ton compte GitHub
était piraté. **Garde cette clé secrète et ne la perds pas** : sans elle, plus aucune mise à jour ne serait acceptée.
Ton propre CoffreFort (ce dossier) ne se connecte jamais à Internet : seules les copies installées le font.

## Remplir les applis Windows (Steam, Battle.net, Epic, Riot…) — Ctrl+Alt+L

Comme l'extension, mais pour les programmes installés :
1. Ouvre la fenêtre de connexion de l'appli et clique dans le champ **identifiant**.
2. Appuie sur **Ctrl+Alt+L** (CoffreFort doit être ouvert et déverrouillé).
3. La première fois, une petite fenêtre te demande quel compte utiliser. Laisse « Toujours utiliser ce compte pour … » coché :
   les fois suivantes, CoffreFort remplit directement, sans rien demander.

CoffreFort tape l'identifiant (ou l'e-mail), Tab, puis le mot de passe, sans valider : tu appuies toi-même sur Entrée.
« Mot de passe seul » sert quand l'identifiant est déjà rempli.

**Plusieurs comptes pour la même appli** (ex. 2 comptes Steam) : associe-les tous ; Ctrl+Alt+L te demande lequel,
avec tes notes. Ou bien sélectionne le compte dans CoffreFort puis fais Ctrl+Alt+L dans l'appli : il est utilisé directement.
**Depuis CoffreFort** : sélectionne un compte puis Ctrl+Alt+L (ou le bouton « ⌨ Remplir l'appli ») : CoffreFort trouve
la fenêtre ouverte de l'appli et la remplit.
**Retirer une association** : bouton « Retirer » dans la fiche du compte, ou « Retirer de cette appli » dans la fenêtre de choix.

Sécurité : la saisie ne vise que la fenêtre qui était active au moment du raccourci, et s'arrête net si une autre
fenêtre passe devant. Les applis associées sont listées dans chaque fiche (« Applis Windows ») et modifiables.
Une appli lancée **en administrateur** refuse la saisie venant d'un programme normal : CoffreFort te le signale.
Si le coffre est verrouillé, CoffreFort s'ouvre ; une fois déverrouillé, la fenêtre de choix apparaît.

## Verrouillage et Windows Hello (⚙ Réglages → Verrouillage et Windows Hello…)

- **Verrouillage avec Windows** (activé par défaut) : CoffreFort se verrouille quand tu verrouilles ta session (Win+L)
  ou quand le PC se met en veille, en plus du verrouillage après 5 minutes sans activité.
- **Déverrouiller avec Windows Hello** (à activer) : après un verrouillage, le bouton « 🖐 Déverrouiller avec Windows Hello »
  rouvre le coffre avec ton code PIN, ton empreinte ou ton visage. Le mot de passe maître reste demandé à chaque démarrage
  de CoffreFort et au moins toutes les 12 heures. Entre-temps, la clé du coffre reste en mémoire, chiffrée par Windows
  pour CoffreFort seul (CryptProtectMemory) ; elle est effacée à la fermeture de l'appli.

## Catégories et favoris

- La barre de gauche filtre : **Tous les comptes**, **★ Favoris**, puis tes **catégories** (Jeux, Réseaux sociaux, Mails,
  Banque, Achats, Travail au départ). « ＋ Nouvelle catégorie » en crée une ; **clic droit** pour la renommer ou la supprimer
  (ses comptes passent « Sans catégorie », rien n'est effacé).
- **Glisser-déposer** : attrape une catégorie dans la barre de gauche pour changer son ordre ; attrape un compte dans la
  liste et lâche-le sur une catégorie pour l'y ranger (sur « Favoris » pour l'ajouter aux favoris, sur « Sans catégorie »
  pour retirer sa catégorie).
- **Favori** : clique sur l'étoile ☆ dans la liste ou en haut de la fiche. Les favoris sont toujours en tête de liste.
- **Catégorie d'un compte** : clique sur la pastille sous son nom dans la fiche, ou choisis-la dans « Modifier ».
  Un compte ajouté pendant qu'une catégorie est affichée y est rangé automatiquement.

## Sauvegarde cloud sans MEGA (OneDrive, Google Drive, Dropbox, iCloud)

CoffreFort détecte les clouds installés sur le PC. Tant qu'aucun dossier de sauvegarde n'est choisi, un bandeau propose
« Sauvegarder dans OneDrive » (ou Google Drive, Dropbox, MEGA…) en un clic. On peut changer à tout moment dans
⚙ Réglages → Sauvegarde automatique. Sans cloud : OneDrive est inclus dans Windows (se connecter avec un compte Microsoft).
Le coffre est copié tel quel, chiffré : le cloud ne voit jamais les mots de passe.
