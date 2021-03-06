
<?php

require_once('config.inc.php');
require_once('db.inc.php');
require_once('manage_users.inc.php');
require_once('manage_unites.inc.php');
require_once('manage_rapports.inc.php');
require_once('display_field.inc.php');
require_once('utils.inc.php');

function displayEditableCandidate($candidate,$report = NULL,$canedit = true)
{
	global $fieldsCandidat;
	global $avis_candidature_necessitant_pas_rapport_sousjury;
	global $fieldsCandidatAvantAudition;
	global $fieldsCandidatAuditionne;

	$hidden = array("action" => "update");

	$session = current_session();

	global $tous_sous_jury;
	$concours = getConcours();

	if($candidate == null) $candidate = (object) null;	
	if($report != NULL)
	{
		$hidden["id_origine"] = $report->id_origine;
		$hidden["type"] = $report->type;
		$rap_audition = needs_audition_report($report);
		if(!$rap_audition)
			$fields = $fieldsCandidatAvantAudition;
		else
			$fields = $fieldsCandidatAuditionne;

		$candidate->rapporteur = $report->rapporteur;
		$candidate->rapporteur2 = $report->rapporteur2;
		$candidate->rapporteur3 = $report->rapporteur3;
		$candidate->type = $report->type;
		$candidate->statut = $report->statut;
		$candidate->id = $report->id;
		$candidate->concours = $report->concours;

		if(isset($report->id_session))
			$session = $report->id_session;
	}
	$submit = array();

	displayEditionFrameStart("",$hidden,$submit);
	displayEditableObject("Candidat(e)",
			 $candidate,
			 $fields,
			$canedit,
			$session,
			 array("conflits"=>'<input type="submit" name="conflit" value="Se déclarer en conflit" />')
			);
	displayEditionFrameEnd("Données candidat");
}

function displayEditableChercheur($chercheur,$report = NULL, $canedit = true)
{

	global $fieldsChercheursAll;
	global $fieldsChercheursDelegationsAll;
	$hidden = array("action" => "update");


	$hidden["previousnom"] = $chercheur->nom;
	$hidden["previousprenom"] = $chercheur->prenom;

	$session = current_session();

	if($report != NULL)
	{
		$hidden["id_origine"] = $report->id_origine;
		$hidden["type"] = $report->type;

		$chercheur->rapporteur = isset($report->rapporteur) ? $report->rapporteur : "";
	        $chercheur->rapporteur2 = isset($report->rapporteur2) ? $report->rapporteur2 : "";
		$chercheur->rapporteur3 = isset($report->rapporteur3) ? $report->rapporteur3 : "";
		$chercheur->type = isset($report->type) ? $report->type : "";
		$chercheur->statut = isset($report->statut) ? $report->statut : "";
		$chercheur->id = $report->id;
		if(isset($report->id_session))
			$session = $report->id_session;

	}

	displayEditionFrameStart("",$hidden,array());

	if(is_current_session_delegation())
	  displayEditableObject("", $chercheur, $fieldsChercheursDelegationsAll, $canedit, $session,
			 array("conflits"=>'<input type="submit" name="conflit" value="Se déclarer en conflit" />'));
	else
	  displayEditableObject("", $chercheur, $fieldsChercheursAll, $canedit, $session,
			 array("conflits"=>'<input type="submit" name="conflit" value="Se déclarer en conflit" />'));

	displayEditionFrameEnd("Données chercheur");

}

function displayEditionFrameStart($titlle, $hidden, $submit)
{

	if($titlle != "")
		echo '<span  style="font-weight:bold;" >'.$titlle.'</span>';

	foreach($hidden as $key => $value)
		echo '<input type="hidden" name="'.$key.'" value="'.$value.'" />'."\n";
	foreach($submit as $key => $value)
		echo '<input type="submit" name="'.$key.'" value="'.$value.'" />'."\n";

}

function displayEditionFrameEnd($titlle)
{
}

function displayEditableField($row, $fieldId, $canedit, $session, $extra_object = "")
{
	global $fieldsAll;
	global $fieldsTypes;
	global $mandatory_edit_fields;
	
	$title = compute_title($row, $fieldId);
	if($title != "" && is_field_visible($row, $fieldId))
	{

		if(isset($fieldsTypes[$fieldId]))
		{
	  		$editable = $canedit && is_field_editable($row, $fieldId);
			if($fieldId === "fichiers")
				if(isset($row->statut) && $row->statut == "audition")
				$editable = true;

			//				echo '<td style="width:20%"><span><B>'.$title.'</B></span>';
				echo '<td><span><B>'.$title.'</B></span>';
			if($fieldsTypes[$fieldId] == "long" || $fieldsTypes[$fieldId] == "treslong")
			echo '</tr><tr>';

			if(!isset($row->$fieldId))
				$row->$fieldId = '';

			if(!$editable && in_array($fieldId, $mandatory_edit_fields))
				echo '<input type="hidden" name="field'.$fieldId.'" value="'.$row->$fieldId.'"/>';
				
			switch($fieldsTypes[$fieldId])
			{
				case "dsi":
					display_dsi($row, $fieldId, !$editable);
					break;
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
					/*
				case "ecole":
					display_ecole($row, $fieldId, !$editable);
					break;
					*/
				case "files":
				  display_fichiers($row, $fieldId, $session, !$editable,"marmotte");
					break;
				case "files_avis":
				  display_fichiers($row, $fieldId, $session, !$editable,"marmotte","avis");
					break;
				case "files_celcc":
				  display_fichiers($row, $fieldId, $session, true,"celcc");
					break;
				case "files_evaluation":
				  display_fichiers($row, $fieldId, $session, true,"e-valuation");
					break;
				case "rapports":
					display_rapports($row, $fieldId);
					break;
				case "statut":
					display_statut2($row, $fieldId, !$editable); break;
				case "type":
					display_type($row, $fieldId, !$editable); break;
				case "sousjury":
					display_sousjury($row, $fieldId, !$editable); break;
			}
		}
	}
	else
		echo "<td></td>\n";
}

function displayEditableObject($titlle, $row, $fields, $canedit, $session, $extra_objects = array())
{
	if($titlle != "")
		echo '<h3>'.$titlle.'</h3>';

	global $fieldsTypes;
	global $mandatory_edit_fields;

	$inline = false;

	$odd = true;

	foreach($fields as  $fieldId)
	{
		$style = is_array($fieldId) ? getStyle($fieldId[0],$odd): getStyle($fieldId,$odd);
		$odd = !$odd;
		echo '<table style="width:100%"><tr class="'.$style.'">'."\n";
		if(is_array($fieldId))
		  {
			foreach($fieldId as $singleField)
			{
				echo '<td style="width:'.strval(round(100/(count($fieldId) ))).'%">';
				echo '<table style="width:100%>'."\n".'<tr class="'.$style.'">'."\n";
				displayEditableField($row, $singleField,$canedit,$session);
			if( isset( $extra_objects[$singleField]) )
			    echo '<td>'.$extra_objects[$singleField].'</td>';
				echo "\n".'</tr></table></td>'."\n";
			}
		}
		else
		{
			echo '<td style="100%"><table><tr class="'.$style.'">'."\n";			
			displayEditableField($row, $fieldId,$canedit,$session);
			if( isset( $extra_objects[$fieldId]) )
			  {
			    //			    echo '<tr class="'.$style.'">';
			    echo '<td>'.$extra_objects[$fieldId].'</td>';
			    //echo '</tr>';
			  }
			echo "\n".'</tr></table></td>'."\n";
		}
		echo '</tr></table>'."\n";
	}
}

function voir_rapport_pdf($row)
{
	$eval_type = $row->type;

	if($eval_type  == REPORT_CANDIDATURE)
	{
	  if(is_auditionne($row))
	    {
		echo "<B>Rapports:</B>";
		if(needs_audition_report($row))
		{
		  //	  throw new Exception("prout");
			echo "<a href=\"export.php?action=viewpdf&amp;option=Audition&amp;id=".$row->id_origine."&amp;id_origine=".$row->id_origine."\">\n";
			echo "d'audition\n";
			echo "</a>\n";
		}
		if(is_classe($row))
		{
			echo "et <a href=\"export.php?action=viewpdf&amp;option=Classement&amp;id=".$row->id_origine."&amp;id_origine=".$row->id_origine."\">\n";
			echo "sur le candidat classé\n";
			echo "</a>\n";
		}
	    }
	}
	else if(!is_equivalence_type($eval_type))
	{
		echo "<a href=\"export.php?action=viewpdf&amp;id=".$row->id_origine."&amp;id_origine=".$row->id_origine."\">\n";
		echo "Voir le rapport de section\n";
		echo "</a>\n";
		
	}

	echo "<br/>";
}

function displayEditableReport($row, $canedit = true)
{
	global $fieldsTypes;
	global $actions;
	global $avis_eval;

	global $statutsRapports;

	global $report_class_to_types;
	global $report_types_to_class;
	
	global $id_rapport_to_label;

	//phpinfo();
	if(!isset($row->id_origine))
		$row->id_origine = 0;

	echo '<div id="debut"></div>';
	echo '<form enctype="multipart/form-data" method="post" action="index.php" style="width: 100%" id="editReport">'."\n";

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

	if($canedit)
		$submits["editprevious"] = "<<";
	else
		$submits["viewprevious"] = "<<";

	if($canedit)
	{
		$submits["submitandkeepediting"] = "Enregistrer";
		$submits["read"] = "Voir";
	}
	else
	{
		if(isSecretaire())
			$submits["submitandkeepviewing"] = "Enregistrer";
		$submits["edit"] = "Editer";
	}

	//	if(isSecretaire())
	//	$submits["deleteandeditnext"] = "Supprimer dernière version";
	$submits["retourliste"] = "Retour à la liste";

	if($canedit)
		$submits["editnext"] = ">>";
	else
		$submits["viewnext"] = ">>";

	$eval_type = $row->type;
	
	$is_unite = is_rapport_unite($row);
		$statut = $row->statut;

	$eval_name = $eval_type;
	global $id_rapport_to_label;
	if(array_key_exists($eval_type, $id_rapport_to_label))
		$eval_name = $id_rapport_to_label[$eval_type];

	$hidden = array(
			"fieldtype" => $eval_type,
			"action" => "update"
			);

	$rapporteurs  = listNomRapporteurs();

	global $typesRapportToFields;

	if(isset($row->id_session))
		$session = $row->id_session;
	else
		$session = current_session();

	$year = substr($session, strlen($session) - 4, 4);

	$nb_rapporteurs = 0;
	$has_rapp = (isset($row->rapporteur) && $row->rapporteur != "");
	$has_rapp2 = (isset($row->rapporteur2) && $row->rapporteur2 != "");
	$has_rapp3 = (isset($row->rapporteur3) && $row->rapporteur3 != "");

	if($has_rapp) $nb_rapporteurs++;
	if($has_rapp2) $nb_rapporteurs++;
	if($has_rapp3) $nb_rapporteurs++;

	if(is_rapport_concours($row))
	{

		if($row->concoursid != "")
		  $candidate = get_candidate_from_concoursid($row->concoursid);
		else 
		  $candidate = get_or_create_candidate($row);
		$candidate->id_session = $row->id_session;
		$candidate->sousjury = $row->sousjury;
		
		//		$row->NUMSIRHUS = $candidate->NUMSIRHUS;
		$conflit = (
				is_in_conflict(getLogin(), $candidate))
				&& !isSecretaire()
				&& !( isset($row->avis) && ($row->avis == "nonauditionne" )
				&& !(isset($row->statut) && ( $row->statut="avistransmis" || $row->statut="publie") ) );

		echo "<div id=\"toolbar\">";
			$titre= "<h3>".$year." / ".$eval_name. ": ". $row->nom." ".$row->prenom.( isset($row->concours)  ? (" / concours ".$row->concours) : ""). ( (isset($row->sousjury) && $row->sousjury != "")  ? (" sousjury ".$row->sousjury) : ""). "</h3>";
		echo $titre;
		displayEditionFrameStart("",$hidden,$submits);
		voir_rapport_pdf($row);
        echo "<div id=\"border-bottom\"></div>";
		echo "</div>";
		if($conflit)
		  {
		    echo "<h2 style=\"color:red;\">Vous êtes en conflit d'intérêt sur cette candidature.</h2>";
		  }
		if(true)
		{
			displayEditableCandidate($candidate,$row,$canedit);

			$other_reports = find_somebody_reports($candidate,$eval_type);


			$fieldsRapportsCandidat0 = $typesRapportToFields[$eval_type][1];
			$fieldsRapportsCandidat1 = $typesRapportToFields[$eval_type][2];
			$fieldsRapportsCandidat2 = $typesRapportToFields[$eval_type][3];
			$fieldsRapportsCandidat3 = $typesRapportToFields[$eval_type][4];

			//			echo $titre;

			$submits = array();

			foreach($other_reports as $report)
				if($report->concours != $row->concours)
				$submits["importconcours".$report->concours] = "Importer données concours ".$report->concours;

			$hidden['fieldconcours'] = $row->concours;
		echo "<br/><hr/><br/>";

				if($conflit)
		  {
		    echo "<h2 style=\"color:red;\">Vous êtes en conflit d'intérêt sur cette candidature.</h2>";
		  }	displayEditableObject("Candidature", $row, array_merge(array("statut"),$fieldsRapportsCandidat0),$canedit, $session);

		echo "<br/><hr/><br/>";

			displayEditionFrameStart("",$hidden,$submits);
				
			if(!$conflit && is_seeing_allowed(getCollege(),$row->type))
			{
				echo'<table><tr>';
				if($has_rapp)
				{
					echo '<td VALIGN="top" style="width: '.(100 / $nb_rapporteurs).'%">';
					displayEditableObject("Prérapport 1".(isset($rapporteurs[$row->rapporteur]) ? (" - ".$rapporteurs[$row->rapporteur]) : (" - ".$row->rapporteur) ),$row,$fieldsRapportsCandidat1,$canedit, $session);
					echo'</td>';
				}
				if($has_rapp2)
				{
					echo '<td VALIGN="top" style="width: '.(100 / $nb_rapporteurs).'%">';
					displayEditableObject("Prérapport 2".(isset($rapporteurs[$row->rapporteur2]) ? (" - ".$rapporteurs[$row->rapporteur2]) : (" - ".$row->rapporteur2) ),$row,$fieldsRapportsCandidat2,$canedit, $session);
					echo'</td>';
				}
				if($has_rapp3)
				{
					echo '<td VALIGN="top" style="width: '.(100 / $nb_rapporteurs).'%">';
					displayEditableObject("Prérapport 3".(isset($rapporteurs[$row->rapporteur3]) ? (" - ".$rapporteurs[$row->rapporteur3]) : (" - ".$row->rapporteur3) ),$row,$fieldsRapportsCandidat3,$canedit, $session);
					echo'</td>';
				}
				echo'</tr></table>';
			}

		}
	}
	else if( is_rapport_chercheur($row) )
	{
		$chercheur = get_or_create_candidate($row);
		$conflit = ( is_in_conflict(getLogin(), $chercheur)) && !isSecretaire()  ;
		
		echo "<div id=\"toolbar\">";
		echo "<h3>".$eval_name. ": ";
		echo (isset($row->id_session) ? $row->id_session : "")." - ";
		echo (isset($row->nom) ? $row->nom : "");
		echo " ".(isset($row->prenom) ? $row->prenom : "")." - ";
		echo (isset($row->DKEY) && $row->DKEY != 0 ? ("(#".$row->DKEY.")") : "")."</h3>";		displayEditionFrameStart("",$hidden,$submits);
		voir_rapport_pdf($row);
		echo "</div>";
		
		if($conflit)
		  {
		    echo "<h2 style=\"color:red;\">Vous êtes en conflit d'intérêt sur cette candidature.</h2>";
		  }
		displayEditableChercheur($chercheur,$row,$canedit);

		//$other_reports = find_somebody_reports($chercheur,$eval_type);
		echo "<br/><hr/><br/>";

		$fieldsIndividual0 = $typesRapportToFields[$eval_type][1];
		$fieldsIndividual1 = $typesRapportToFields[$eval_type][2];
		$fieldsIndividual2 = $typesRapportToFields[$eval_type][3];
		$fieldsIndividual3 = $typesRapportToFields[$eval_type][4];

			



		if(!$conflit && (is_seeing_allowed(getCollege(),$row->type)))
		{
			displayEditionFrameStart("",$hidden,array());

			echo'<table  style="width:100%"><tr>';
			if($has_rapp)
			{
				echo '<td valign="top" style="width: '.(100 / $nb_rapporteurs).'%">';
				displayEditableObject("Prérapport 1".(isset($rapporteurs[$row->rapporteur]) ? (" - ".$rapporteurs[$row->rapporteur]) : (" - ".$row->rapporteur) ),$row,$fieldsIndividual1,$canedit, $session);
				echo'</td>';
			}
			if($has_rapp2)
			{
				echo '<td valign="top" style="width: '.(100 / $nb_rapporteurs).'%">';
				displayEditableObject("Prérapport 2".(isset($rapporteurs[$row->rapporteur2]) ? (" - ".$rapporteurs[$row->rapporteur2]) : (" - ".$row->rapporteur2) ),$row,$fieldsIndividual2,$canedit, $session);
				echo'</td>';
			}
			if($has_rapp3)
			{
				echo '<td valign="top" style="width: '.(100 / $nb_rapporteurs).'%">';
				displayEditableObject("Prérapport 3".(isset($rapporteurs[$row->rapporteur3]) ? (" - ".$rapporteurs[$row->rapporteur3]) : (" - ".$row->rapporteur3) ),$row,$fieldsIndividual3,$canedit, $session);
				echo'</td>';
			}
			echo '</tr></table>';
		}
			echo "<br/><hr/><br/>";
		displayEditableObject("Rapport section", $row,$fieldsIndividual0, $canedit, $session);
	}
	else// if( is_rapport_unite($row) )
	{
		$units = unitsList();
		if(!isset($typesRapportToFields[$eval_type]))
		  $eval_type = REPORT_INCONNU;

		$fieldsUnites0 = $typesRapportToFields[$eval_type][1];
		$fieldsUnites1 = $typesRapportToFields[$eval_type][2];
		$fieldsUnites2 = $typesRapportToFields[$eval_type][3];
		$fieldsUnites3 = $typesRapportToFields[$eval_type][4];

		/*
		global $fieldsUnitesExtra;

		if(key_exists($eval_type,$fieldsUnitesExtra))
			$fieldsUnites0 = array_merge($fieldsUnitesExtra[$eval_type],$fieldsUnites0);
			*/
		echo "<div id=\"toolbar\">";

		$hidden["action"] = "update";
		$hidden["create_new"] = true;
		$hidden["id_origine"] = $row->id_origine;
		
				echo "<h3>".$eval_name. ": ". (isset($row->unite) ? $row->unite : "");
		echo (isset($row->DKEY) && $row->DKEY != 0 ? ("(#".$row->DKEY .")") : "")."</h3>";
		displayEditionFrameStart("",$hidden,$submits);
		voir_rapport_pdf($row);
		echo "</div>"; 
	
		displayEditionFrameStart("",$hidden,array());

		echo'<table><tr>';


		if(isset($row->rapporteur) && $row->rapporteur != "")
		{
		  echo'<td valign="top"	style="width: '.(100 / $nb_rapporteurs).'%">';
					displayEditableObject("Prérapport 1".(isset($rapporteurs[$row->rapporteur]) ? (" - ".$rapporteurs[$row->rapporteur]) : (" - ".$row->rapporteur) ),$row,
$fieldsUnites1, $canedit, $session);
			echo'</td>';
		}
		if(isset($row->rapporteur2) && $row->rapporteur2 != "")
		{
		  echo'<td valign="top" style="width: '.(100 / $nb_rapporteurs).'%">';
					displayEditableObject("Prérapport 2".(isset($rapporteurs[$row->rapporteur2]) ? (" - ".$rapporteurs[$row->rapporteur2]) : (" - ".$row->rapporteur2) ),$row,
$fieldsUnites2, $canedit, $session);
			echo'</td>';
		}
		if(isset($row->rapporteur3) && $row->rapporteur3 != "")
		{
		  echo'<td valign="top"	style="width: '.(100 / $nb_rapporteurs).'%">';
					displayEditableObject("Prérapport 3".(isset($rapporteurs[$row->rapporteur3]) ? (" - ".$rapporteurs[$row->rapporteur3]) : (" - ".$row->rapporteur3) ),$row,
$fieldsUnites3, $canedit, $session);
			echo'</td>';
		}

		echo'</tr></table>';
			echo "<br/><hr/><br/>";
		displayEditableObject("Rapport section", $row,$fieldsUnites0, $canedit, $session);

	}

	echo "</form>\n";
					?>
					<script>
					   $('input').click(function() { sessionStorage.scrollPos = $(window).scrollTop(); return true;  });
	     window.onload = function () {  $(window).scrollTop(sessionStorage.scrollPos || 0); };
					</script>
					    <?php
}

function editReport($id_rapport)
{
	try
	{
		$report = getReport($id_rapport);
		
		for($i = 0 ; $i < count($_SESSION['rows_id']); $i++)
			if($_SESSION['rows_id'][$i] == $id_rapport)
			$_SESSION['current_id'] = $i;
		
		$row = normalizeReport($report);

		displayEditableReport($row, true);
	}
	catch(Exception $exc)
	{
		throw new Exception("Echec de l'édition du rapport:\n ".$exc->getMessage());
	}
};

function viewReport($id_rapport)
{
	try
	{
		$report = getReport($id_rapport);
		
		for($i = 0 ; $i < count($_SESSION['rows_id']); $i++)
			if($_SESSION['rows_id'][$i] == $id_rapport)
			$_SESSION['current_id'] = $i;
		
		if($report->section != currentSection())
			throw new Exception("Visualisation interdite, ce rapport est un rapport de la section/CID ".$report->section);

		$row = normalizeReport($report);
		displayEditableReport($row, false);
	}
	catch(Exception $exc)
	{
		throw new Exception("Echec de l'édition du rapport:\n ".$exc->getMessage());
	}

};



?>
