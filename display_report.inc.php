<?php

require_once('config.inc.php');
require_once('db.inc.php');
require_once('manage_users.inc.php');
require_once('manage_unites.inc.php');
require_once('manage_rapports.inc.php');
require_once('display_field.inc.php');
require_once('utils.inc.php');

function displayEditableCandidate($candidate,$report = NULL)
{

	global $fieldsCandidat;
	global $avis_candidature_necessitant_pas_rapport_sousjury;
	global $fieldsCandidatAvantAudition;

	$hidden = array("action" => "update");

	$hidden["previousnom"] = $candidate->nom;
	$hidden["previousprenom"] = $candidate->prenom;
	
	if($report != NULL)
	{
		$hidden["id_origine"] = $report->id_origine;
		$hidden["fieldanneecandidature"] = session_year($report->id_session);
		$hidden["type"] = $report->type;
		$hidden["id_session"] = $report->id_session;
		if(isset($report->avis) && in_array($report->avis, $avis_candidature_necessitant_pas_rapport_sousjury))
			$fields = $fieldsCandidatAvantAudition;

	}


	echo '<h1>Candidat(e) : '.$candidate->nom." ".$candidate->prenom." ".'</h1>';

	displayEditionFrameStart("",$hidden,array());

	displayEditableObject("", $candidate, $fieldsCandidat);

	displayEditionFrameEnd("Données candidat");

}

function displayEditableChercheur($chercheur,$report = NULL)
{
	global $fieldsChercheursAll;
	

	$hidden = array("action" => "update");


	$hidden["previousnom"] = $chercheur->nom;
	$hidden["previousprenom"] = $chercheur->prenom;
	
	if($report != NULL)
	{
		$hidden["id_origine"] = $report->id_origine;
		$hidden["type"] = $report->type;
		$hidden["id_session"] = "all";
	}

	echo '<h1>Chercheur(se) : '.$chercheur->nom." ".$chercheur->prenom." ".'</h1>';

	displayEditionFrameStart("",$hidden,array());

	displayEditableObject("", $chercheur, $fieldsChercheursAll);

	displayEditionFrameEnd("Données");

}


function displayEditionFrameStart($titlle, $hidden, $submit)
{
	echo "<!-- displayEditableObject ".$titlle." -->\n";

	if($titlle != "")
		echo '<span  style="font-weight:bold;" >'.$titlle.'</span>';

	foreach($hidden as $key => $value)
		echo '<input type="hidden" name="'.$key.'" value="'.$value.'" />'."\n";
	foreach($submit as $key => $value)
		echo '<input type="submit" name="'.$key.'" value="'.$value.'" />'."\n";

}

function displayEditionFrameEnd($titlle)
{
	echo "<!-- Fin de displayEditableObject ".$titlle." -->\n";
}

function displayEditableObject($titlle, $row, $fields, $use_special_tr = true)
{
	global $fieldsAll;

	if($titlle != "")
		echo '<table><tr><td><span  style="font-weight:bold;" >'.$titlle.'</span></td></tr>';
	else
		echo '<table>';


	global $specialtr_fields;
	global $start_tr_fields;
	global $end_tr_fields;
	global $fieldsAll;
	global $fieldsTypes;
	global $mandatory_edit_fields;

	$inline = false;

	$odd = true;
	foreach($fields as  $fieldId)
	{
		if(isset($fieldsAll[$fieldId]) && is_field_visible($row, $fieldId))
		{
			$style = getStyle($fieldId,$odd);
			$odd = !$odd;
			$title = $fieldsAll[$fieldId];
			if(isset($fieldsTypes[$fieldId]))
			{
				
				$editable = is_field_editable($row, $fieldId);

				/*
				if(!$use_special_tr || !in_array($fieldId, $specialtr_fields) || in_array($fieldId, $start_tr_fields))
					echo '<tr>';
					*/
					echo '<tr class="'.$style.'">';
				echo '<td style="width: 10em;" ><span>'.$title.'</span>';
				echo '</td>';

/*
				if($use_special_tr && in_array($fieldId, $start_tr_fields))
					echo '<td><table><tr>';
*/
				if(!isset($row->$fieldId))
					$row->$fieldId = '';


				if(!$editable && in_array($fieldId, $mandatory_edit_fields))
					echo '<input type="hidden" name="field'.$fieldId.'" value="'.$row->$fieldId.'"/>';

				switch($fieldsTypes[$fieldId])
				{
					case "enum":
						display_enum($row, $fieldId, !$editable);
						break;
					case "topic":
						display_topic($row, $fieldId, !$editable);
						break;
					case "long":
						display_long($row, $fieldId, !$editable);
						break;
					case "treslong":
						display_treslong($row, $fieldId, !$editable);
						break;
					case "short":
						display_short($row, $fieldId, !$editable);
						break;
					case "avis":
						display_avis($row, $fieldId, !$editable);
						break;
					case "rapporteur":
						display_rapporteur($row, $fieldId, !$editable);
						break;
					case "unit":
						display_unit($row, $fieldId, !$editable);
						break;
					case "grade":
						display_grade($row, $fieldId, !$editable);
						break;
					case "concours":
						display_concours($row, $fieldId, !$editable);
						break;
					case "ecole":
						display_ecole($row, $fieldId, !$editable);
						break;
					case "files":
						display_fichiers($row, $fieldId, !$editable);
						break;
					case "statut":
						display_statut2($row, $fieldId, !$editable); break;
					case "type":
						display_type($row, $fieldId, !$editable); break;
					case "sousjury":
						display_sousjury($row, $fieldId, !$editable); break;
				}
				/*
				if(!$use_special_tr || !in_array($fieldId, $specialtr_fields))
				*/
					echo '</tr>';
				
					/*
				if($use_special_tr && in_array($fieldId, $end_tr_fields))
					echo '</tr></table></td></tr>';
					*/
			}
				
		}

	}
	?>
</table>
<?php 

}

function displayEditableReport($row, $canedit = true)
{
	global $fieldsAll;
	global $fieldsTypes;
	global $actions;
	global $avis_eval;

	global $typesRapports;
	global $statutsRapports;

	global $typesRapportsChercheurs;
	global $typesRapportsConcours;
	global $typesRapportsUnites;


	//phpinfo();
	echo '<div id="debut"></div>';
	echo '<form enctype="multipart/form-data" method="post" action="index.php" style="width: 100%">'."\n";


	if(!isset($row->id_origine))
		$row->id_origine = 0;

	$next = next_report($row->id_origine);
	$previous = previous_report($row->id_origine);

	$hidden = array(
			"next_id" => strval($next),
			"previous_id" => strval($previous),
			"action" => "update",
			"create_new" => true,
			"id_origine" => $row->id_origine
	);

	$submits = array();
	$submits["editprevious"] = "<<";
	
	if(isReportEditable($row))
		$submits["submitandkeepediting"] = "Enregistrer";
	
	if(isSecretaire())
		$submits["deleteandeditnext"] = "Supprimer";
	$submits["retourliste"] = "Retour à la liste";
	$submits["editnext"] = ">>";

	displayEditionFrameStart("",$hidden,$submits);

		$eval_type = $row->type;
		$is_unite = array_key_exists($eval_type,$typesRapportsUnites);
		$statut = $row->statut;

		$eval_name = $eval_type;
		if(array_key_exists($eval_type, $typesRapports))
			$eval_name = $typesRapports[$eval_type];


		$hidden = array("fieldtype" => $eval_type);

		if(array_key_exists($eval_type, $typesRapportsConcours))
		{
			$candidate = get_or_create_candidate($row);
			displayEditableCandidate($candidate,$row);
			
			$other_reports = find_somebody_reports($candidate,$eval_type);
			//rrr();
			echo "<br/><hr/><br/>";
				
			global $fieldsRapportsCandidat0;
			global $fieldsRapportsCandidat1;
			global $fieldsRapportsCandidat2;


			echo "<h1>".$eval_name. ": ". $row->nom." ".$row->prenom.(isset($row->concours) ? (" / concours ".$row->concours) : ""). " (rapport #".(isset($row->id) ? $row->id : " New").")</h1>";



			$submits = array();


			foreach($other_reports as $report)
				if($report->concours != $row->concours)
				{
					$submits["importconcours".$report->concours] = "Importer données concours ".$report->concours;
				}

				$hidden['fieldconcours'] = $row->concours;

				displayEditionFrameStart("",$hidden,$submits);

				echo'<table><tr>';
				
				if(isset($row->rapporteur) && $row->rapporteur != "")
				{
					echo '<td VALIGN="top">';
					displayEditableObject("Prérapport 1",$row,$fieldsRapportsCandidat1);
					echo'</td>';
				}
				
				if(isset($row->rapporteur2) && $row->rapporteur2 != "")
				{
					echo '<td VALIGN="top">';
					displayEditableObject("Prérapport 2", $row,$fieldsRapportsCandidat2);
										echo'</td>';
				}
				
				
				echo'</tr></table>';

				displayEditableObject("Rapport section", $row, array_merge(array("statut"),$fieldsRapportsCandidat0));
		}
		else if(array_key_exists($eval_type, $typesRapportsChercheurs))
		{
			//todo $chercheur = chercheur_of_report($row);
			$chercheur = get_or_create_candidate($row);
			displayEditableChercheur($chercheur,$row);
				
			$other_reports = find_somebody_reports($chercheur,$eval_type);
			echo "<br/><hr/><br/>";
				
			global $fieldsIndividual0;
			global $fieldsIndividual1;
			global $fieldsIndividual2;

			echo "<h1>".$eval_name. ": ". (isset($row->nom) ? $row->nom : "")." ".(isset($row->prenom) ? $row->prenom : "");
			echo " (".(isset($row->id) && $row->id != 0 ? "#".$row->id : "New").")</h1>";


			displayEditionFrameStart("",$hidden,array());

			echo'<table><tr>';

			if(isset($row->rapporteur) && $row->rapporteur != "")
			{
				echo '<td VALIGN="top">';
				displayEditableObject("Prérapport 1", $row,$fieldsIndividual1, false);
					echo'</td>';
			}

			if(isset($row->rapporteur2) && $row->rapporteur2 != "")
			{
				echo '<td VALIGN="top">';
				displayEditableObject("Prérapport 2",$row,$fieldsIndividual2, false);
				echo'</td>';
			}
			
			echo '</tr></table>';
			displayEditableObject("Rapport section", $row,$fieldsIndividual0, false);
				
			

		}
		else if(array_key_exists($eval_type, $typesRapportsUnites))
		{
			$units = unitsList();


			global $fieldsUnites0;
			global $fieldsUnites1;
			global $fieldsUnites2;
				
			echo "<h1>".$eval_name. ": ". (isset($row->unite) ? $row->unite : "")." (#".(isset($row->id) && $row->id != 0 ? $row->id : "New").")</h1>";

			displayEditionFrameStart("",$hidden,array());

			echo'<table><tr><td VALIGN="top">';
			displayEditableObject("Rapport section", $row,$fieldsUnites0, false);

			if(isset($row->rapporteur) && $row->rapporteur != "")
			{
				echo'</td><td VALIGN="top">';
				displayEditableObject("Prérapport 1", $row,$fieldsUnites1, false);
			}
			if(isset($row->rapporteur2) && $row->rapporteur2 != "")
			{
				echo'</td><td VALIGN="top">';
				displayEditableObject("Prérapport 2",$row,$fieldsUnites2, false);
			}
				
			echo'</td></tr></table>';


		displayEditionFrameEnd("Données rapport");

		echo "</form>\n";
	}
	echo('
					<script type="text/javascript">');
	echo('
					document.getElementById("debut").scrollIntoView();');

	/*
	 echo('
	 		var elt = document.getElementById( '$id' );
	 		var top = (	return elt.offsetTop + ( elt.offsetParent ? elt.offsetParent.documentOffsetTop() : 0 )) - ( window.innerHeight / 2 );
	 		window.scrollTo( 0, top );
	 		');
	*/
	echo('		</script>');

}


function editReport($id_rapport)
{
	try
	{
		$report = getReport($id_rapport);
		$canedit = isReportEditable($report);
		$row = normalizeReport($report);
		$candidat = get_or_create_candidate($row);
		displayEditableReport($row, $canedit);
	}
	catch(Exception $exc)
	{
		throw new Exception("Echec de l'édition du rapport:\n ".$exc->getMessage());
	}

};


function displayActionsMenu($row, $excludedaction = "", $actions)
{
	$id = $row->id;
	$id_origine = $row->id_origine;
	echo "<table><tr>";
	foreach($actions as $action => $actiondata)
		if ($action!=$excludedaction)
		{
			$title = $actiondata['title'];
			$icon = $actiondata['icon'];
			$page = $actiondata['page'];
			$level = $actiondata['level'];
			if(getUserPermissionLevel() >= $level )
			{

				echo "<td>\n<a href=\"$page?action=$action&amp;id=$id&amp;id_origine=$id_origine\">\n";
				echo "<img class=\"icon\" width=\"24\" height=\"24\" src=\"$icon\" alt=\"$title\"/>\n</a>\n</td>\n";
			}
		}
		echo "</tr></table>";
}




function displaySummary($filters, $filter_values, $sorting_values)
{
	global $fieldsSummary;
	global $fieldsSummaryConcours;
	global $typesRapports;
	global $statutsRapports;
	global $filtersReports;
	global $fieldsTypes;

	$rows = filterSortReports($filters, $filter_values, $sorting_values);

	$rows_id = array();
	foreach($rows as $row)
		$rows_id[] = $row->id;
	$_SESSION['rows_id'] = $rows_id;


	$fields = is_current_session_concours() ? $fieldsSummaryConcours : $fieldsSummary;

	if(isSecretaire())
		$fields = array_unique(array_merge($fields,array("date","auteur","id","statut")));


	//Remove the type filter if useless
	if($filter_values['type'] != $filters['type']['default_value'] )
	{
		$new_field = array();
		foreach($fields as $field)
			if($field != 'type')
			$new_field[] = $field;
		$fields = $new_field;
	}


	displayRows($rows,$fields, $filters, $filter_values, getCurrentSortingList(), $sorting_values);
}



?>