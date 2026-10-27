"""Nouveautés de chaque version, affichées une fois après la mise à jour (la plus récente en premier).

À chaque publication, ajouter une entrée en tête avec le numéro que publier.py va donner
(dernière version publiée + 1).
"""

NOTES = [
    (14, "Santé du coffre", [
        "Nouveau dans la barre de gauche : 🩺 Santé du coffre. Elle repère les mots de passe faibles, "
        "réutilisés (ou presque identiques) et ceux pas changés depuis plus d'un an, avec une note sur 100.",
        "En option : vérifier si tes mots de passe apparaissent dans des fuites connues (Have I Been Pwned). "
        "Ton mot de passe ne quitte jamais le PC.",
        "Un bouton « Changer » sur chaque compte concerné.",
    ]),
    (13, "Sécurité renforcée", [
        "Le téléphone n'accepte plus qu'une demande d'association à la fois.",
        "Appli Android 1.2 : installe-la depuis le bouton « Installer » de l'appli.",
    ]),
    (12, "Appli Android", [
        "Consulte et copie tes mots de passe sur ton téléphone Android, même sans réseau (lecture seule).",
        "Le téléphone se met à jour tout seul sur ton Wi-Fi, et s'ouvre avec ton mot de passe maître ou ton empreinte.",
        "⚙ Réglages → Téléphone Android… pour l'installer et l'associer.",
    ]),
    (11, "Pages de l'extension MEGA", [
        "Sur la page de connexion de l'extension MEGA (que le navigateur interdit de remplir), CoffreFort propose "
        "tes comptes MEGA avec des boutons « Copier ».",
        "La copie est faite par CoffreFort : invisible dans l'historique du presse-papiers et effacée après 20 secondes.",
    ]),
    (10, "Fenêtre des nouveautés", [
        "Après chaque mise à jour, cette fenêtre te montre ce qui a changé.",
        "Tu peux la revoir à tout moment : ⚙ Réglages → Nouveautés…",
    ]),
    (9, "Glisser-déposer", [
        "Change l'ordre des catégories en les faisant glisser dans la barre de gauche.",
        "Glisse un compte sur une catégorie pour l'y ranger, sur « Favoris » pour l'ajouter aux favoris.",
    ]),
    (8, "Sauvegarde cloud pour tous", [
        "CoffreFort trouve OneDrive, Google Drive, Dropbox, iCloud ou MEGA et propose d'y sauvegarder ton coffre "
        "chiffré en un clic.",
    ]),
    (7, "Nouveau design, catégories et favoris", [
        "Nouveau thème sombre et barre latérale : Tous les comptes, Favoris, Catégories.",
        "Clique sur l'étoile ☆ pour mettre un compte en favori, sur la pastille sous son nom pour le ranger.",
    ]),
    (6, "Verrouillage et Windows Hello", [
        "CoffreFort se verrouille quand tu verrouilles Windows (Win+L) ou que le PC se met en veille.",
        "Option : déverrouiller avec ton code PIN, ton empreinte ou ton visage (Réglages → Verrouillage).",
        "Ctrl+Alt+L : plusieurs comptes par appli, notes affichées, associations modifiables.",
    ]),
    (5, "Extension : bon dossier", [
        "L'extension te prévient si elle est chargée depuis le mauvais dossier et t'indique le bon.",
    ]),
    (4, "Remplissage des applis Windows", [
        "Ctrl+Alt+L remplit l'identifiant et le mot de passe dans Steam, Battle.net, Epic…",
    ]),
    (3, "Vérifier les mises à jour", [
        "Réglages → Mises à jour… affiche ta version et cherche une mise à jour en un clic.",
    ]),
    (2, "Pseudo et e-mail", [
        "Chaque compte peut avoir un pseudo et un e-mail séparés ; l'extension remplit chacun au bon endroit.",
    ]),
]

LATEST = NOTES[0][0]


def since(version):
    """Entrées plus récentes que `version` (au plus 3, pour ne pas noyer après une longue absence)."""
    return [n for n in NOTES if n[0] > version][:3]
