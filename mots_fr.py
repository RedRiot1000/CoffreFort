"""Mots français courants pour les phrases de passe (noms, adjectifs, verbes faciles à taper et à retenir).
Chaque mot tiré au hasard ajoute log2(nombre de mots) bits d'aléa : ~11 bits pour ~2000 mots."""

_RAW = """
abeille abricot accent acier acteur action adresse affiche agneau aigle aiguille aile aimant air album alcool algue allee
allumette alpage amande ambre ami amiral amour ampoule ananas ancre ange angle anneau annee antenne appel appareil arbre
arc arche ardoise argent argile armoire arome arrosoir art artiste asperge assiette astre atelier atlas atome aube auberge
aurore autobus automne autruche avenir averse avion aviron avocat avoine avril azur badge bagage bague baguette baie
baignoire bain balade balai balcon baleine balise ballon bambou banane banc bandeau banjo banque baobab baril barque barre
bassin bateau baton baume bazar beignet belette berceau berger beton beurre biberon biche bijou bille biscuit bison bitume
blague blason bleuet bloc blouse bobine bocal bois boisson boite bol bonbon bonnet bord borne bosquet botte bouche boucle
boue bougie bouillon boule bouquet bourgeon boussole bouteille bouton bracelet branche bras brebis brique brise brioche
brocoli brosse brouette brume bruit buche buffet buisson bulle bureau buste cabane cabine cable cacao cactus cadeau cadre
cafe cage cahier caillou caisse calcul calendrier calme camion campagne canal canard canne canoe canon cantine cap cape
capitaine capuche carafe caramel caravane carnet carotte carre carte carton cascade casque casserole castor cave ceinture
celeri cerceau cerf cerise cerveau chaise chaleur chalet chambre chameau champ chandelle chanson chant chapeau charbon
chariot chateau chaton chaudron chausson chemin cheminee chemise chene chenille cheval chevre chien chiffon chocolat
chou chouette ciel cigale cigogne cime cinema cirque ciseau citron citrouille clairiere clarinette classe clavier cle
clocher clou clown cobra cochon coffre coin col colibri colline colombe comete commode compas comptoir concert concombre
condor confiture copain coq coquille corbeau corde corne cornichon costume coton cou couche coude couleur coupe cour
courage couronne courrier course coussin couteau couvercle crabe craie crayon creme crepe crevette cristal crochet
crocodile croissant cube cuillere cuir cuisine cuivre cumin cygne dahlia dame danse dauphin de debut decor defi delta
dent desert dessin destin detour diamant dinde dindon disque docteur doigt domino donjon dossier douane douche dragon
drap drapeau dune duvet eau echarpe echelle eclair ecole ecorce ecran ecrou ecureuil effort eglise elan elephant elfe
email embarras emeraude encre enfant enigme envol epee epice epinard epingle eponge equipe erable escalier escargot espace
espoir essence etable etage etang etoile etui evasion eventail facteur faisan falaise famille fanfare farine faucon
fauteuil fee fenetre fer ferme feu feuille feutre fiole figue fil filet flamant flamme flaque fleche fleur fleuve flocon
flute foin fontaine foret forge fortune fosse fou foudre fougere four fourche fourmi fraise framboise frein frene friandise
frigo fromage front fruit fumee fusee gant garage gare gateau gaufre gazelle gazon gecko gel genou geste girafe glace
gland globe gomme gorille goutte gouvernail graine grange grappe grenier grenouille griffe grille grotte groupe guepe
guepard guitare hamac hamster hareng haricot harpe hache hameau hangar hautbois herbe heron hibou hiver homard horizon
horloge hotel houx huile huitre humour hutte hyene iceberg ile image indice insecte iris ivoire jade jambon jardin jeton
jeu joie jonquille joue jouet journal judo jument jungle jupe jus kayak kiwi koala lac lacet laine lait laitue lama lampe
lance lande langue lanterne lapin laser laurier lavande legume lettre levier lezard liane libellule licorne lien lierre
lievre ligne lilas limace lime limonade lin lion lit livre loge loup loupe luge lumiere lune lutin lynx macaron magie
maillot main maison manege mangue manteau marais marche mare marmotte marron masque matelas matin medaille melon menthe
mer merle meteore meuble miel mimosa miroir mitaine moineau montagne montre morse mouette moulin mousse moustache mouton
muguet mur muse musique myrtille nacre nappe navire neige nenuphar nid noisette noix nomade nougat nuage nuit oasis ocean
odeur oeuf oignon oiseau olive ombre ongle opale or orage orange orchestre ordinateur oreille oreiller orge orme ortie os
otarie ouragan ours outil ouvrage paille pain palais palmier pamplemousse panda panier panneau pantalon papier papillon
paquet parapluie parc parfum passage pastel pate patin paume pavot pays peche peigne peinture pelle pelouse pendule pensee
perle perroquet persil phare phoque piano pic pierre pigeon pilote piment pin pinceau pingouin pion pirate piscine piste
pivert pizza placard plage plaine planche planete plante plateau plume pluie poche poele poeme poire poireau pois poisson
poivre pole pomme pompe pont porte portail pot potager pouce poule poulpe poupee prairie prune puce puits pull puma pyramide
quai quartz radeau radis rafale raisin rame rampe rangee rateau rayon recette refuge reglisse reine renard requin reseau
reve riviere riz robe robot rocher roi roman ronce rose roseau roue ruban ruche rue ruisseau sable sabot sac safran salade
salon sandale sapin sardine satin sauce saule saumon savon scie seau secret seigle sel selle semaine sentier serpent
serre sifflet signal silence singe sirene sirop ski soleil sommet son sorbet souris sous sport statue stylo sucre
sureau table tableau tablier tache taille tambour tampon tapis tasse taupe taureau temple tempete tente terre terrier
tete the theatre thon tigre tilleul timbre tiroir tissu toile toit tomate tonneau tonnerre torche tortue toupie tour
tournesol train traineau tram tresor tribu tricot trompette tronc trophee trou truite tulipe tunnel turban tuyau univers
usine vache vague valise vallee valse vanille vapeur vase veau velo vent verger verre vigne village ville violon vipere
vitrail voile voilier volcan voyage wagon yaourt zebre zero
agile aimable ancien aride audacieux beau blanc bleu bon bref brillant brun calme carre chaud cher clair cosmique court
creux curieux dense doux droit dur epais etrange fier fin fort fou frais franc froid geant gentil gros habile haut heureux
humble immense jaune jeune joli joyeux large leger lent libre lisse loin long lourd magique malin mauve mince moderne
mou muet neuf noble noir nouveau ocre orange ouvert pale petit plat plein poli propre pur rapide rare ravi rond rose rouge
roux rude sage sauvage secret serein simple solide sombre souple stable subtil sucre super tendre tiede timide tranquille
tropical vaste vert vieux vif violet vivant zen
aimer aller apprendre arriver avancer bondir bouger briller calmer cacher chanter chercher choisir compter conduire
courir creer crier danser deviner dessiner dormir ecouter ecrire entrer envoyer explorer filer flotter fondre frapper
gagner garder glisser grandir grimper jouer lancer lire manger marcher monter nager naviguer offrir oublier ouvrir partir
penser plonger porter pousser prendre ranger regarder rentrer rever rire rouler sauter sentir siffler skier sourire
suivre tirer tomber tourner trouver vibrer voler voyager
abri abysse acajou acrobate affaire agenda agrume aiglon aileron aimer airelle alarme alezan alibi aliment allure alpaca
alpin amandier amazone ambulance amiante ampleur anchois anecdote anemone animal anis anorak antilope aquarium araignee
arbitre arbuste arcade archer arene arete argus armure arpent arsenal artichaut asile astuce atout aubergine aubepine
audace autel avalanche avenue aventure aveu axe azalee babouin bacon badaud bagnole baladin balance balcon balle banjo
banquise baraque barbe barreau basilic basson bataille batterie baudet bavard beaute becasse beluga benjamin bequille
berline betail betterave biche bidon bilan billard binette biplan bivouac blaireau blizzard blouson bobsleigh bocage
boheme bolide bombe bonheur bonsai bordure bosse botanique bouc bouclier boudin bouee bouleau boulon bourdon bourrasque
boxeur braise brancard brasier bretelle bricole brigade brindille brochet bronze brouillard bruyere buffle bulldozer
burin buvard caban cabri cachette cadenas cafard caillou calepin calice calumet camelia camembert camomille canape
canari candeur caniche canif cannelle canotier cantate capsule capucine carabine carambole carapace caribou carillon
carlin carrosse cartable casbah casino cassis castagnette catapulte caverne cedre cellule cendre centaure cepage
cerfeuil chaine chalumeau chamois chandail chanvre chapelle charade charcutier chardon charpente charrue chasseur
chataigne chaume chevalier chevalet chicoree chimere chiot chorale chrome cible cidre ciment cintre cirage citadelle
civette clairon clementine clepsydre cloche cloison clovis coccinelle cocon coeur colibri collier colosse comptine
conque console corail corbeille cordage cormoran corniche corsaire cortege cosmos cotillon coucou couleuvre coulisse
coupole courbe courgette coyote crapaud cratere crayon creneau crepuscule cresson criquet crique croquet crotale
cuirasse cumulus curcuma cyclone cypres dague dalle damier dattier debardeur decibel delice demon denier dentelle
derive descente diademe diapason digue diligence dinosaure dirigeable discours distance dolmen dorade dortoir doublure
dragee dromadaire druide duel duo eboueur ecaille echalote echasse echo eclipse ecluse ecume edredon elixir embleme
empire enclume encens endive engrenage entrepot epave epervier epi epopee equerre ermite escale escrime espadon esquimau
estampe estuaire etalon etincelle etrier eucalyptus fable facette fagot faience falot fanal farandole fardeau farfadet
faucille fennec fermoir festin feuillage fiacre ficelle figurine filament flambeau flanelle fleuret flibustier flotte
foulard fourneau fragment fregate fresque friche frimas fronde fuseau gabarit gadget galet galion gargouille garrigue
gazette gemme genet geyser gilet gingembre girouette glacier glaieul glaive gnome goeland golfe gondole gong gouache
goudron gourde gourmet grain granit gratin gravier griffon grillon guetteur gui guimauve guirlande gymnase hallebarde
harmonica harpon havre hermine heros hetre hirondelle horde houblon houle hublot hydre hysope icone igloo impala
infante iode jacinthe jaguar jasmin javelot jockey jongleur jujube kimono kiosque lagon lagune laiton lamelle lampion
landau lapis larme lasso latte laureat lessive lichen limon linotte loriot lotus loutre lucarne luciole lupin luth
macareux magnolia maillet mammouth mandarine mangouste manoir mante marbre marelle margelle marin marmite marteau
martinet mascotte massue mat matador mazurka meandre medaillon melodie menhir merlan mesange metronome meunier
micro migrateur millet minaret minerai minotaure mirabelle mistral mocassin moellon moka molosse momie monocle mosaique
mouflon mousqueton muscade musee mustang myrtille narcisse narval navet nectar neon nougatine noyau nymphe obelisque
obus ocelot octave odyssee ogre ombrelle onyx opera orbite ordre origan orme ortolan ouistiti ourlet ozone pagaie
pagode paillette palette palourde pampa panache panthere paon papyrus parchemin parquet pastille patio patrouille
pavillon pelican pendentif penombre pepite periscope perle pervenche petale petrole phalange pharaon phenix pieuvre
pilier pinson pipeau pirogue pistache pivoine plancton platane plomb plumeau polaire pollen pommade pompon porcelaine
portique potiron poudre pradeau pralin prisme proue puzzle python quartier quenouille quiche quille rabot racine
radar radio raie rameau rapace raquette ravin rebond recif regate relais remous renne repaire rempart reptile requiem
resine rideau rivage rodeo roitelet romarin roquette rossignol rotin roulotte rubis rugby sablier safari saphir sarbacane
satellite saturne saxophone scarabee sceptre scooter scorpion sequoia serrure sextant silex sillon sitar sloop smoking
soie sorcier soufre soupir sphinx spirale stalactite steppe store sumo surf tabouret talisman tamarin tamis tanin
tapir tatou teck temoin tenor terrasse tetras thym tiare tipi tison toboggan tonnelle topaze torrent totem toucan
toundra tourbillon tourelle tramway trapeze trefle treillis trident trimaran triton troene troubadour trousseau tuba
tuile turquoise typhon ukulele valet vallon vanneau varan velours venus verveine vestige viaduc vigie vinaigre
violette virage viseur volute vortex yack yeti yoga zenith zephyr zinc zodiaque
"""

WORDS = tuple(sorted(w for w in set(_RAW.split()) if 3 <= len(w) <= 12))
