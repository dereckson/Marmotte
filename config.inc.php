<?php
	include "configDB.inc.php";
	
	
	define("president","Frédérique Bassino");
	define("president_titre","Présidente de la Section 6");
	define("secretaire","Hugo Gimbert");
	define("section_nb","6");
	define("section_fullname","Section 6 du CoNRS");
	define("section_intitule","Sciences de l'information : fondements de l'informatique, calculs, algorithmes, représentations, exploitations");
	
	
	
	$fieldsSummary = array(
		"nom",
		"prenom",
		"grade",
		"unite",
		"type",
		"rapporteur",
		"date",
	);

	$fieldsAll = array(
		"concours" => "Concours",
		"ecole" => "Ecole",
		"nom" => "Nom",
		"prenom" => "Prenom",
		"unite" => "Unité",
		"grade" => "Grade",
			/* paramètre important à mettre en tête*/
		"anciennete_grade" => "Ancienneté dans grade",
		"type" => "Type",
		"rapporteur" => "Rapporteur",
			/*Hugo: j'ai besoin de l'avis et du rapport en tête pour éditer vite.
			 * Remarque qu'en plus ça devrait accélérer la présentation des prérapports par les prérapporteurs
			* qui commenceront par la conclusion puis étayerons avec qques points
			* au lieu de présenter tout le dossier avant de le synthétiser*/
			"avis" => "Proposition d'avis",
			"rapport" => "Proposition de rapport",
		"prerapport" => "Points marquants",
		"date_recrutement" => "Date de recrutement",
		"production" => "Production scientifique",
		"production_notes" => "Production scientifique",
		"transfert" => "Transfert et valorisation",
		"transfert_notes" => "Détails transfert/valorisation",
		"encadrement" => "Encadrement",
		"encadrement_notes" => "Détails sur l'encadrement",
		"responsabilites" => "Responsabilités collectives",
		"responsabilites_notes" => "Détails responsabilités",
		"mobilite" => "Mobilité",
		"mobilite_notes" => "Détails sur la mobilité",
		"animation" => "Animation scientifique",
		"animation_notes" => "Détails sur l'animation",
		"rayonnement" => "Rayonnement",		
		"rayonnement_notes" => "Détails sur le rayonnement",		
		"auteur" => "Auteur Dernière(s) modif(s)",
		"date" => "Date modification",
	);

	$fieldsIndividual = array(
			"nom",
			"prenom",
			"unite",
			"grade",
			"anciennete_grade",
			"rapporteur",
			"avis",
			"rapport",
			"prerapport",
			"date_recrutement",
			"production",
			"production_notes",
			"transfert",
			"transfert_notes",
			"encadrement",
			"encadrement_notes",
			"responsabilites",
			"responsabilites_notes",
			"mobilite",
			"mobilite_notes",
			"animation",
			"animation_notes",
			"rayonnement",
			"rayonnement_notes"
	);

	$fieldsCandidat = array(
			"concours",
			"nom",
			"prenom",
			"rapporteur",
			"avis",
			"rapport",
			"prerapport",
			"production",
			"production_notes",
			"transfert",
			"transfert_notes",
			"encadrement",
			"encadrement_notes",
			"responsabilites",
			"responsabilites_notes",
			"mobilite",
			"mobilite_notes",
			"animation",
			"animation_notes",
			"rayonnement",
			"rayonnement_notes"
	);
	
	$fieldsUnites = array(
		"unite",
		"rapporteur",
		"rapport",
		"prerapport",
		"avis",
		"auteur",
		"date"
	);

	$fieldsEcoles = array(
			"ecole",
			"nom",
			"prenom",
			"unite",
			"rapporteur",
			"rapport",
			"prerapport",
			"avis",
			"auteur",
			"date"
	);
	
	$examples = array(
		"nom" => "Doe",
		"prenom" => "John",
		"grade" => "DRCE",
		"unite" => "UMR 6666 (HELL)",
		"concours" => "06/01",
		"ecole" => "Ecole de Pythagore",
		"type" => "Promotion",
		"rapporteur" => "Anne ONYME",
		"prerapport" => "Candidat au fort potentiel, proche de la retraite ...",
		"anciennete_grade" => "~4 ans",
		"date_recrutement" => "1999",
		"production" => "A-",
		"production_notes" => "Nombreuses revues et conférences ...",
		"transfert" => "A",
		"transfert_notes" => "Un brevet et quelques logiciels diffusés ...",
		"encadrement" => "B",
		"encadrement_notes" => "Un étudiant en thèse, quelques stagiaires de M2 ...",
		"responsabilites" => "A+",
		"responsabilites_notes" => "Membre du comité national ...",
		"mobilite" => "C",
		"mobilite_notes" => "Peu de visites, en poste dans son labo de thèse ...",
		"animation" => "A+",
		"animation_notes" => "Jongle et joue de l'harmonica tout en présidant son GDR ...",
		"rayonnement" => "B+",		
		"rayonnement_notes" => "Travaux assez cités relativement aux pratiques de son domaine ...",		
		"rapport" => "La section 06 vous invite à renouveler votre garde robe. ..",
		"avis" => "Réservé",
		"auteur" => "joe",
		"date" => "3/02/2013",
	);

	$empty_report = array(
		"id_session" => "",
		"nom" => "",
		"prenom" => "",
		"grade" => "",
		"unite" => "",
		"ecole" => "",
		"concours" => "",
		"type" => "",
		"rapporteur" => "",
		"prerapport" => "",
		"anciennete_grade" => "",
		"date_recrutement" => "",
		"production" => "",
		"production_notes" => "",
		"transfert" => "",
		"transfert_notes" => "",
		"encadrement" => "",
		"encadrement_notes" => "",
		"responsabilites" => "",
		"responsabilites_notes" => "",
		"mobilite" => "",
		"mobilite_notes" => "",
		"animation" => "",
		"animation_notes" => "",
		"rayonnement" => "",		
		"rayonnement_notes" => "",		
		"rapport" => "",
		"avis" => "",
		"auteur" => "",
		"date" => date(DATE_RSS),
		"id_origine" => "0"
	);
		

	$fieldsTypes = array(
		"ecole" => "ecole",
		"concours" => "concours",
		"nom" => "short",
		"prenom" => "short",
		"grade" => "grade",
		"unite" => "unit",
		"type" => "short",
		"rapporteur" => "rapporteur",
		"avis" => "avis",
		"rapport" => "treslong",
		"prerapport" => "treslong",
		"anciennete_grade" => "short",
		"date_recrutement" => "short",
		"production" => "evaluation",
		"production_notes" => "long",
		"transfert" => "evaluation",
		"transfert_notes" => "long",
		"encadrement" => "evaluation",
		"encadrement_notes" => "long",
		"responsabilites" => "evaluation",
		"responsabilites_notes" => "long",
		"mobilite" => "evaluation",
		"mobilite_notes" => "long",
		"animation" => "evaluation",
		"animation_notes" => "long",
		"rayonnement" => "evaluation",		
		"rayonnement_notes" => "long",		
		"auteur" => "short",
		"date" => "short",
	);
	
	$fieldsEdit = array(
		"id" => "Identifiant",
		"nom" => "Nom",
		"prenom" => "Prenom",
	);
	
	$typesRapportsIndividuels = array(
		'Evaluation-Vague' => 'Evaluation à Vague',
		'Evaluation-MiVague' => 'Evaluation à Mi-Vague',
		'Promotion' => 'Promotion',
		'Candidature' => 'Candidature',
		'Suivi-PostEvaluation' => 'Suivi Post-Evaluation',
		'Titularisation' => 'Titularisation',
		'Affectation' => 'Confirmation d\'Affectation'
	);

	$typesRapportsUnites = array(
			'Changement-Directeur' => 'Changement de Directeur',
			'Changement-Directeur-Adjoint' => 'Changement de Directeur Adjoint',
			'Renouvellement' => 'Renouvellement',
			'Expertise' => 'Expertise',
			'Ecole' => 'Ecole Thematique',
			'Comite-Evaluation' => 'Comité d\'Evaluation',
			'Generique' => 'Générique'
	);
	
	$typesRapports = array_merge($typesRapportsIndividuels, $typesRapportsUnites);
		
	/* Définition des avis possibles pour chaque type de rapport*/
	
	/* Pour les evals à vague et mi vague*/
	$avis_eval = array(
			""=>"",
			"favorable" => "Favorable",
			"differe" => "Différé",
			"reserve" => "Réservé",
			"alerte" => "Alerte"
	);

	/* Pour les promos*/
	$avis_classement = array(""=>"", "non"=>"<em>non-classé</em>", "oui"=>"Oui", "1"=>"<B>1</B>", "2"=>"<B>2</B>", "3"=>"<B>3</B>", "4"=>"<B>4</B>",
			 "5"=>"<B>5</B>", "6"=>"<B>6</B>", "7"=>"<B>7</B>" , "8"=>"<B>8</B>", "9"=>"<B>9</B>"
			, "10"=>"<B>10</B>", "11"=>"<B>11</B>", "12"=>"<B>12</B>", "13"=>"<B>13</B>", "14"=>"<B>14</B>", "15"=>"<B>15</B>", "16"=>"<B>16</B>",
			 "17"=>"<B>17</B>", "18"=>"<B>18</B>", "19"=>"<B>19</B>",
			 "20"=>"<B>20</B>", "21"=>"<B>21</B>");

	/* Pour les concours*/
	$avis_candidature = array(""=>"", "nonauditionne"=>"<em>Non Auditionné</em>", "oral"=>"Auditionné", "nonclasse"=>"<em>non-classé</em>", "1"=>"<B>1</B>", "2"=>"<B>2</B>", "3"=>"<B>3</B>", "4"=>"<B>4</B>",
			 "5"=>"<B>5</B>", "6"=>"<B>6</B>", "7"=>"<B>7</B>" , "8"=>"<B>8</B>", "9"=>"<B>9</B>"
			, "10"=>"<B>10</B>", "11"=>"<B>11</B>", "12"=>"<B>12</B>", "13"=>"<B>13</B>", "14"=>"<B>14</B>", "15"=>"<B>15</B>", "16"=>"<B>16</B>",
			 "17"=>"<B>17</B>", "18"=>"<B>18</B>", "19"=>"<B>19</B>",
			 "20"=>"<B>20</B>", "21"=>"<B>21</B>");
	
	/* Pour les SPE par exemple*/
	$avis_vide = array(""=>"");

	$avis_binaire = array(
			""=>"",
			"favorable" => "Favorable",
			"reserve" => "Réservé",
			"differe" => "Différé",
			"sansavis" => "Pas d'avis"
	);

	$avis_ternaire = array(
			""=>"", 
			"tresfavorable" => "Très Favorable",
			"favorable" => "Favorable",
			"reserve" => "Réservé",
			"differe" => "Différé",
			"sansavis" => "Pas d'avis"
	);

	$avis_ecoles = array(
			""=>"",
			"tresfavorable" => "Très Favorable",
			"favorable" => "Favorable",
			"defavorable" => "Défavorable",
			"sansavis" => "Pas d'avis"
	);
	
	$avis_pertinence = array(
			""=>"",
			"tresfavorable" => "Très Favorable",
			"favorable" => "Favorable",
			"defavorable" => "Défavorable",
			"reserve" => "Réservé",
			"sansavis" => "Pas d'avis"
	);
	
	/* Types d'avis disponibles dans l'interface pour chaque type de rapport*/
	$typesRapportToAvis = array(
		'Evaluation-Vague' => $avis_eval,
		'Evaluation-MiVague' => $avis_eval,
		'Promotion' => $avis_classement,
		'Candidature' => $avis_candidature,
		'Suivi-PostEvaluation' => $avis_vide,
		'Affectation' => $avis_binaire,
		'Titularisation' => $avis_binaire,
		'Changement-Directeur' => $avis_pertinence,
		'Changement-Directeur-Adjoint' => $avis_pertinence,
		'Renouvellement' => $avis_pertinence,
		'Expertise' => $avis_pertinence,
		'Ecole' => $avis_ecoles,
		'Comite-Evaluation' => $avis_binaire,
		'Generique' => $avis_vide,
		);
	

/* Definition des checkboxes à la fin de certains rapports*/
	
	/*Pour les evals à vague et mi vague*/
	$evalCheckboxes = array(
			"favorable" => "<B>Avis favorable</B>	
	<small> (l’activité du chercheur est conforme à ses obligations statutaires)</small>",
			"differe" => "<B>Avis différé</B>
<small> (l’évaluation est renvoyée à la session suivante en raison de l’insuffisance ou de l'absence d'éléments du dossier)</small>",
			"reserve" => "<B>Avis réservé</B>
<small> (la section a identifié dans l’activité du chercheur un ou plusieurs éléments qui nécessitent un suivi spécifique)</small>",
			"alerte" => "<B>Avis d'alerte</B>
<small> (la section exprime des inquiétudes sur l’évolution de l’activité du chercheur))</small>");

	/* Pour les renouvellements de gdr ou création d'unités*/
	$pertinenceCheckboxes = array(
			"tresfavorable" => "<B>Avis très favorable</B>",
			"favorable" => "<B>Avis favorable</B>",
			"defavorable" => "<B>Avis défavorable</B>",
			"reserve" => "<B>Avis réservé</B>",
			"sansavis" => "Pas d'avis"
		);

	/* Pour les écoles thématiques*/
	$ecoleCheckboxes = array(
			"tresfavorable" => "<B>Avis très favorable</B>",
			"favorable" => "<B>Avis favorable</B>",
			"defavorable" => "<B>Avis défavorable</B>"
	);
	
	$typesRapportsToCheckboxes = array(
	'Evaluation-Vague' => $evalCheckboxes,
	'Evaluation-MiVague' => $evalCheckboxes,
	'Renouvellement' => $pertinenceCheckboxes,
	'Expertise' => $pertinenceCheckboxes,
	'Ecole' => $ecoleCheckboxes
	);

	$typesRapportsToCheckboxesTitles = array(
			'Evaluation-Vague' => '<B>EVALUATION A VAGUE DE CHERCHEUR<br/>Avis de la section sur l’activité du chercheur</B>',
			'Evaluation-MiVague' => '<B>EVALUATION A MI-VAGUE DE CHERCHEUR<br/>Avis de la section sur l’activité du chercheur</B>',
			'Renouvellement' => '<B>AVIS DE PERTINENCE DU SOUTIEN DU CNRS AUX UNITES</B>',
			'Expertise' => '<B>AVIS DE PERTINENCE DU SOUTIEN DU CNRS AUX UNITES</B>',
			'Ecole' => '<B>AVIS SUR L\'ECOLE</B>'
	);
	

	$typesRapportsToEnteteGauche = array(
			'Evaluation-Vague' => '<B>Objet de l’évaluation :</B><br/><EM>évaluation à vague de chercheur</EM>',
			'Evaluation-MiVague' => '<B>Objet de l’évaluation :</B><br/><EM>évaluation à mi-vague de chercheur</EM>',
			'Promotion' => '<B>Objet de l’évaluation :</B><br/>Avancement de grade<br/><B>Au grade de :</B>',
			'Candidature' => '<B>Objet de l’évaluation :</B><br/><EM>Candidature au concours</EM>',
			'Suivi-PostEvaluation' => '<B>Objet de l’évaluation :</B><br/><EM>Suivi post-évaluation</EM>',
			'Affectation' => '<B>Objet de l’évaluation :</B><br/>Affectation',
			'Titularisation' => '<B>Objet de l’évaluation :</B><br/>Titularisation',
			'Changement-Directeur' =>  '<B>Objet de l’évaluation :</B><br/>Changement de directeur',
			'Changement-Directeur-Adjoint' =>  '<B>Objet de l’évaluation :</B><br/>Changement de directeur adjoint',
			'Renouvellement' => '<B>Objet de l’examen :</B> <EM>avis de pertinence d’association au CNRS : renouvellement</EM>',
			'Association' => '<B>Objet de l’examen :</B> <EM>avis de pertinence d’association au CNRS : projet d\'association</EM>',
			'Expertise' => '<B>Objet de l’examen :</B> <EM>expertise</EM>',
			'Ecole' => '<B>Objet de l’évaluation :</B><br/> Ecole Thématique',
			'Comite-Evaluation' => '<B>Objet de l’examen :</B> Comité d\'évaluation',
			'Generique' => '<B>Rapport</B>',
	);

	$enTetesDroit = array(
			'Individu' => '<B>Nom, prénom et affectation du chercheur :</B><br/>',
			'Concours' => '<B>Classement, nom et prénom du candidat :</B><br/>',
			'Unite' => '<B>Code, intitulé et nom<br/>du directeur de l’unité :</B><br/>',
			'Ecole' => '<B>Nom de l\'école et du porteur de projet :</B><br/>',
			'PromotionDR' => '<B>Classement, nom et unité :</B><br/>',
			'' => 'Objet'
			);
	
	$typesRapportsToEnteteDroit = array(
			'Evaluation-Vague' => 'Individu',
			'Evaluation-MiVague' => 'Individu',
			'Promotion' => 'Individu',
			'Candidature' => 'Concours',
			'Suivi-PostEvaluation' => 'Individu',
			'Affectation' => 'Individu',
			'Titularisation' => 'Individu',
			'Changement-Directeur' =>  'Unite',
			'Changement-Directeur-Adjoint' =>  'Unite',
			'Renouvellement' => 'Unite',
			'Association' => 'Unite',
			'Expertise' => 'Unite',
			'Ecole' => 'Ecole',
			'Comite-Evaluation' => 'Unite',
			'Generique' => '',
	);
	
	
/* Definition des formaules standards à la fin de certains rapports*/
	
	$promotionFormula = array(
			'non'=> 'Le faible nombre de possibilités de promotions DR1 cette année ne permet malheureusement pas à la Section 6 du Comité National de proposer ce chercheur à la Direction Générale du CNRS pour une promotion cette année.'
			);
	
	$typesRapportsToFormula = array(
		'Promotion' => $promotionFormula,
			);

	
/* Definition des différents grades*/
	
	$grades = array(
		'CR2' => 'Chargé de Recherche 2ème classe (CR2)',
		'CR1' => 'Chargé de Recherche 1ère classe (CR1)',
		'DR2' => 'Directeur de Recherche 2ème classe (DR2)',
		'DR1' => 'Directeur de Recherche 1ère classe (DR2)',
		'DRCE1'  => 'Dir. de Recherche Classe Except. 1er échelon (DRCE1)',
		'DRCE2'  => 'Dir. de Recherche Classe Except. 2ème échelon (DRCE2)',
		'ChaireMC' => 'Chaire MC',
		'ChairePR' => 'Chaire PR',
		'Emerite' => 'Emerite',
		'MC' => 'MC',
		'PR' => 'PR',
		'PhD' => 'PhD',
		'HDR' => 'Habilité à diriger des recherches',
		'None' => 'Pas de grade'
	);
	
/* Definition des différentes notes*/
	$notes = array(
		' ',
		'A+',
		'A',
		'A-',
		'B+',
		'B',
		'B-',
		'C+',
		'C',
		'C-',
	);
	
	$actions = array(
		'details' => "Détails", 
		'history' => "Historique", 
		'edit'  => "Modifier"
	);
	
	$typeExports = array(
			"pdf" => 	array(
					"mime" => "application/x-pdf",
					"xsl" => "",
					"name" => "XML",
			),
			"xml" => 	array(
					"mime" => "text/xml",
					"xsl" => "xslt/xmlidentity.xsl",
					"name" => "XML",
			),
			"latex" => 	array(
					"mime" => "application/x-latex",
					"xsl" => "",
					"name" => "Zip",
			),
			"html" => 	array(
					"mime" => "text/html",
					"xsl" => "xslt/html2.xsl",
					"name" => "Html",
			),
			"htmlmin" => 	array(
					"mime" => "text/html",
					"xsl" => "xslt/htmlminimaledit.xsl",
					"name" => "Html",
			),
	);
	
	
	$concours_ouverts = array(
			"",	"06/01", "06/02", "06/03"
			)
	
?>