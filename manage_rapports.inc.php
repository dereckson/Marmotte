<?php

require_once('manage_sessions.inc.php');
require_once('manage_unites.inc.php');
require_once('manage_people.inc.php');
require_once("config.inc.php");

require_once('manage_filters_and_sort.inc.php');

function compute_title($row, $fieldId)
{
	global $id_rapport_to_label;
	global $fieldsAll;

	$title = "";
	if( substr($fieldId, 0, 4) == "Info" )
	{
		global $add_rubriques_people;
		global $add_rubriques_candidats;

		$suff = intval(substr($fieldId,4));

		if( is_rapport_chercheur($row) )
			$title = $add_rubriques_people[$suff];
		else if( is_rapport_concours($row) )
			$title = $add_rubriques_candidats[$suff];
	}
	else if( substr($fieldId, 0, 7) == "Generic" )
	{
		global $add_rubriques_concours;
		global $add_rubriques_chercheurs;
		global $add_rubriques_unites;

		$suff = intval(substr($fieldId,7))/3;

		if( is_rapport_chercheur($row) )
			$title = $add_rubriques_chercheurs[$suff];
		else if( is_rapport_concours($row) )
			$title = $add_rubriques_concours[$suff];
		else if( is_rapport_unite($row) )
			$title = $add_rubriques_unites[$suff];
	}
	else if(isset($fieldsAll[$fieldId]))
		$title = $fieldsAll[$fieldId];

	/*global $type_specific_fields_renaming;
	 if(isset($row->type) && key_exists($row->type, $type_specific_fields_renaming) && key_exists($fieldId, $type_specific_fields_renaming[$row->type]))
		$title = $type_specific_fields_renaming[$row->type][$fieldId];
	if(isset($row->intitule))
		$title .= " - ".$row->intitule;
	*/

	return $title;
}

function getIDOrigine($id_rapport)
{
	if($id_rapport <= 0)
		return 0;

	$sql = "SELECT id_origine FROM ".reports_db." WHERE id=$id_rapport";
	$result=sql_request($sql);
	$report = mysqli_fetch_object($result);
	if($report == false)
	{
		throw new Exception("No report with id ".$id_rapport);
	}
	else
		return $report->id_origine;
}


function deleteCurrentSelection()
{
	if(isset($_SESSION['rows_id']))
	{
		$rows_id = $_SESSION['rows_id'];
		$errors = "";
		$n = count($rows_id) -1;
		for($i = 0; $i <= $n; $i++)
			try {
			deleteReport($rows_id[$i], true);
		}
		catch(Exception $e)
		{
			$errors .= "Failed to delete report with id ".$rows_id[$i].": ".$e."\n<br/>";
		}
		if($errors != "")
			throw new Exception($errors);
	}

}
/*
 * returns an object
*/

function getDSIReport($DKEY)
{
	$sql = "SELECT * FROM ".dsidbname.".".dsi_evaluation_db." WHERE DKEY=\"".$DKEY."\";";
	$res = sql_request($sql);
	while($row = mysqli_fetch_object($res))
		return $row;

	$sql = "SELECT * FROM ".dsidbname.".".dsi_evaluation_units_db." WHERE DKEY=\"".$DKEY."\";";
	$res = sql_request($sql);
	while($row = mysqli_fetch_object($res))
		return $row;
	
	return null;	
}

function getReport($id_rapport, $most_recent = true)
{
	if($most_recent)
		$id_rapport = getIDOrigine($id_rapport);
	$sql = "SELECT * FROM ".reports_db." WHERE id=$id_rapport";
	$result=sql_request($sql);
	$report = mysqli_fetch_object($result);

	if($report == false)
	{
		throw new Exception("No report with id ".$id_rapport);
	}
	else
		return normalizeReport($report);
}

function reportShortSummary($report)
{
	$nom = $report->nom;
	$prenom = $report->prenom;
	$grade = $report->grade_rapport;
	$unite = $report->unite;
	$type = $report->type;
	$session = "Session ".$report->id_session;
	if($type == "Promotion")
	{
		switch($grade)
		{
			case "CR2": $grade = "CR1"; break;
			case "DR2": $grade = "DR1"; break;
			case "DR1": $grade = "DRCE1"; break;
			case "DRCE1": $grade = "DRCE2"; break;
		}
		$grade .= " - ".$avis;
	}

	if(is_rapport_unite($report) )
		return $session." - ".$type." - ".$report->unite;
	else
		return $session." - ".$type." - ".$grade." - ".$nom."_".$prenom;

}


function getAllReportsOfType($type,$id_session=-1)
{

	if($id_session==-1)
		$id_session = current_session_id();
	$filter_values = array('type'=> $type,'id_session' => $id_session);

	return filterSortReports(getCurrentFiltersList(), $filter_values);
}

function filterSortReports($filters, $filter_values = array(), $sorting_value = array(), $rapporteur_or = true)
{
	$section = $_SESSION['filter_section'];
	$sql = "SELECT *, ".reports_db.".id AS report_id, ".people_db.".id AS people_id, ".people_db.".nom AS people_nom, ".people_db.".prenom AS people_prenom, ".people_db.".conflits AS people_conflits, ".reports_db.".nom AS nom, ".reports_db.".prenom AS prenom FROM ".reports_db;
	$sql .=" left join ".people_db." on ".reports_db.".nom=".people_db.".nom AND ".reports_db.".prenom=".people_db.".prenom AND ".reports_db.".section=".people_db.".section WHERE ";
	$sql .= reports_db.".id=".reports_db.".id_origine AND ".reports_db.".statut!=\"supprime\" AND ".reports_db.".section=\"".$section."\"";
	//$sql = "SELECT * FROM ".reports_db." WHERE id = id_origine AND statut!=\"supprime\"";
	//$sql = "SELECT * FROM ".reports_db." WHERE date = (SELECT MAX(date) FROM evaluations AS mostrecent WHERE mostrecent.id_origine = evaluations.id_origine AND statut!=\"supprime\")";
	//$sql = "SELECT * FROM ( SELECT id, MAX(date) AS date FROM evaluations GROUP BY id_origine) mostrecent ON tt.date = mostrecent.date";
	//$sql = "SELECT * FROM evaluations WHERE (SELECT id, MAX(date) AS date FROM evaluations GROuP BY id_origine) AS X "
	//$sql = "SELECT tt.*, ss.nom AS nom_session, ss.date AS date_session FROM evaluations tt INNER JOIN ( SELECT id, MAX(date) AS date FROM evaluations GROUP BY id_origine) mostrecent ON tt.date = mostrecent.date, sessions ss WHERE ss.id=tt.id_session ";
	//$sql = "SELECT * FROM evaluations WHERE 1 ";


	$sql .= filtersCriteriaToSQL($filters,$filter_values, $rapporteur_or);
	$sql .= sortCriteriaToSQL($sorting_value);
	$sql .= ";";

	//echo $sql;
	$result=sql_request($sql);

	if($result == false)
		throw new Exception("Echec de l'execution de la requete <br/>".$sql."<br/>");

	$rows = array();
	//echo $sql."<br/>".count($rows)." rows ".mysqli_num_rows($result)." sqlrows<br/>";

	while ($row = mysqli_fetch_object($result))
	{
		$row->id = $row->report_id;
		$rows[] = $row;
	}

	return $rows;
}


function sortCriteriaToSQL($sorting_values)
{
	global $fieldsIndividualAll;
	global $fieldsRapportAll;

	$sql = "";

	foreach($sorting_values as $crit => $value)
	{
		$sql .= ($sql == "") ? "ORDER BY " : ", ";

		if(isset($fieldsRapportAll[$crit]))
			$pref = reports_db.".";
		else if(isset($fieldsIndividualAll[$crit]))
			$pref = people_db.".";
		else
		{
			throw new Exception("Sort criterion ".$crit." is neither in the list of rapport fields nor in the list of individual fields");
		}

		$sql .= $pref.$crit." ".( ( substr($sorting_values[$crit],strlen($sorting_values[$crit]) -1) == "+" ) ? "ASC" : "DESC");
	}

	return $sql;
}

function filtersCriteriaToSQL($filters, $filter_values, $rapporteur_or = true)
{
	global $fieldsTypes;

	global $fieldsRapportAll;
	global $fieldsIndividualAll;

	$sql = "";
	foreach($filters as $filter => $data)
	{

		if(isset($filter_values[$filter]) && (!isset($data['default_value']) || $filter_values[$filter] != $data['default_value']))
		{

			if($filter == "rapporteur" && $rapporteur_or)
			{
				//dirty hack to have an OR clause on rapporteurs...
				$val = $filter_values[$filter];
				$sql .= " AND (".reports_db.".rapporteur=\"".$val."\" OR ".reports_db.".rapporteur2=\"".$val."\" OR ".reports_db.".rapporteur3=\"".$val."\") ";
			}
			else if($rapporteur_or && $filter =="rapporteur2")
			{
				continue;
			}
			else if($rapporteur_or && $filter =="rapporteur3")
			{
				continue;
			}
			else if($filter == "avancement")
			{
				$login = "";
				if(isset($filter_values["rapporteur"]))
					$login = $filter_values["rapporteur"];

				//dirty hack tfor "Mes rapport sà faire/ faits"
				$val = $filter_values[$filter];

				if($login != "")
					$basesql = "( (".reports_db.".rapporteur=\"$login\" AND ".reports_db.".avis1 != \"\") OR (".reports_db.".rapporteur2=\"$login\" AND ".reports_db.".avis2 != \"\") OR  (".reports_db.".rapporteur3!=\"$login\" AND ".reports_db.".avis3 != \"\")) ";
				else
					$basesql = "( (".reports_db.".rapporteur=\"\" OR ".reports_db.".avis1 != \"\") AND (".reports_db.".rapporteur2=\"\" OR ".reports_db.".avis2 != \"\") AND (".reports_db.".rapporteur3=\"\" OR ".reports_db.".avis3 != \"\")) ";

				if($val == "todo")
					$sql .= " AND NOT ".$basesql;
				else if($val == "done")
					$sql .= " AND ".$basesql;
			}
			else if($filter == "concours")
			{
				global $concours_ouverts;
				if(isset($filter_values[$filter]))
				{
					$val = $filter_values[$filter];
					$listeconcours = array();
					//gere le cas de "concours=CR" dans ce cas il faut générer r.g. "concours=0602 OR concours=0603"
					foreach($concours_ouverts as $code => $intitule)
						if($val == $code ||  strncmp($intitule, $val, strlen($val)) == 0)
						$listeconcours[] = $code;
					if(count($listeconcours) == 0)
						continue;
					$first = true;
					$sql .= " AND (";
					$field = (isset($data['sql_col']) ?  $data['sql_col'] : $filter);
					foreach($listeconcours as $code)
					{
						$sql .= ($first ? "" : " OR ".reports_db.".") . $field."=\"$code\" ";
						$first = false;
					}
					$sql .= " ) ";
				}
			}
			else if(isset($fieldsTypes[$filter]) && $fieldsTypes[$filter] == "avis")
			{
				if($filter_values[$filter] == "classe")
					$sql .= " AND (".reports_db.".$filter REGEXP \"c^[0-9]\" OR ".reports_db.".$filter=\"classe\") ";
				else if($filter_values[$filter] == "oral")
					$sql .= " AND (".reports_db.".$filter=\"oral\" OR ".reports_db.".$filter=\"nonclasse\" OR ".reports_db.".$filter REGEXP \"^[0-9]\" )";
				else if($filter_values[$filter] == "admisaconcourir")
					$sql .= " AND ".reports_db.".$filter!=\"nonconcur\" AND ".reports_db.".$filter!=\"desistement\" ";
				else
					$sql .= " AND ".reports_db.".$filter=\"$filter_values[$filter]\" ";
			}
			else
			{
				if(isset($fieldsRapportAll[$filter]))
					$pref = reports_db.".";
				else if(isset($fieldsIndividualAll[$filter]))
					$pref = people_db.".";
				else
					throw new Exception("Filter criterion ".$filter." is neither in the list of rapport fields nor in the list of individual fields");

				$sql .= " AND ". (isset($data['sql_col']) ?  $data['sql_col'] : ($pref.$filter))."=\"$filter_values[$filter]\" ";
			}

		}
	}
	//echo $sql;
	return $sql;
}

function getTriTypes($sorting_values)
{
	$result = array();
	$result[(count($sorting_values) + 5)."+"] = "";
	for($i = 1; $i < count($sorting_values) + 5 ; $i++)
	{
		$result[ $i."+"] = $i."+";
		$result[ $i."-"] = $i."-";
	}
	return $result;
}


function getStatus($id_rapport)
{
	$report = getReport($id_rapport);
	return $report->statut;
}

function isReportEditable($rapport)
{
	try
	{
		checkReportIsEditable($rapport);
		return true;
	}
	catch(Exception $exc)
	{
		return false;
	}
}

function checkReportIsEditable($rapport)
{
	$login = getLogin();

	if (isBureauUser())
	{
		return true;
	}
	else if($rapport->statut != "doubleaveugle" && $rapport->statut != "prerapport")
	{
		throw new Exception("Ce rapport n'a plus le statut de prerapport et n'est donc plus éditable par ses rapporteurs. Si nécessaire veuillez demander un changement de statut au secrétaire.");
	}
	else if($rapport->type == REPORT_CANDIDATURE)
	{
		$concours = $rapport->concours;
		$sousjury = $rapport->sousjury;
		global $tous_sous_jury;
		if(isset($tous_sous_jury[$concours]) &&  isset($tous_sous_jury[$concours][$sousjury]) && $login == $tous_sous_jury[$concours][$sousjury]["president"])
			return true;
	}
	else if( ($rapport->rapporteur != "") && ($rapport->rapporteur != $login) && ($rapport->rapporteur2 != $login)&& ($rapport->rapporteur3 != $login))
		throw new Exception("Vous n'êtes pas rapporteur<br/>. Si nécessaire veuillez demander un changement de rapporteur au bureau.");
	else
		return true;
}

function checkReportDeletable($rapport)
{
	if (isSecretaire() && $rapport->statut == 'publie')
		throw new Exception("Les rapports publies ne sont pas supprimables, changer d'abord le statut du rapport");
	else if (isSecretaire())
		return true;
	else if( $rapport->rapporteur != getLogin())
		throw new Exception("Le rapporteur de ce rapport est ".$rapport->rapporteur." mais vous êtes loggés sous l'identité ".getLogin());
	else if ($rapport->statut != 'doubleaveugle')
		throw new Exception("Ce rapport a le statut ".$rapport->statut." et n'est donc pas supprimable, seuls les prérapports sont supprimables par un rapporteur.");
	else
		return true;
}

function isReportCreatable()
{
	return isSecretaire();
}

function deleteReport($id_rapport, $all_versions = false)
{
	$report = getReport($id_rapport);

	checkReportDeletable($report);

	$report = getReport($id_rapport);

	//Finding newest report before this one, if exists, and making it the newest
	$sql = "SELECT * FROM ".reports_db." WHERE date = (SELECT MAX(date) FROM ".reports_db." AS mostrecent WHERE mostrecent.id_origine=$id_rapport AND mostrecent.id != $id_rapport AND mostrecent.statut!=\"supprime\")";
	$result= sql_request($sql);

	$before = mysqli_fetch_object($result);
	if($before != false && !$all_versions)
	{
		$previous_id = $before->id;
		$sql = "UPDATE ".reports_db." SET id_origine=".intval($previous_id)." WHERE id_origine=".intval($id_rapport)." ;";
		sql_request($sql);
	}

	if(!$all_versions)
	{
		$sql = "DELETE FROM ".reports_db." WHERE id=".intval($id_rapport)." ;";
		sql_request($sql);
	}
	else
	{
		$sql = "DELETE FROM ".reports_db." WHERE id_origine=".intval($id_rapport)." ;";
		sql_request($sql);
	}

	return ($before !=false) ? $before->id : -1;
};

function newReport($type_rapport)
{
	if(!isReportCreatable())
		throw new Exception("Vous n'avez pas les droits nécessaires à la création d'un rapport. Veuillez contacter le secrétaire scientifique.");

	$row = array();
	$row['type'] = $type_rapport;
	$row["DKEY"] = "";
	$row['section'] = $_SESSION['filter_section'];

	return normalizeReport($row);
} ;

function addReport($report)
{
	if(!isReportCreatable())
		throw new Exception("Le compte ".$login." n'a pas la permission de créer un rapport, veuillez contacter le secrétaire scientifique.");

	global $empty_report;

	foreach($empty_report as $key => $value)
		if(!isset($report->$key))
		$report->$key = $value;

	if(!isSuperUser())
		$report->section = $_SESSION['filter_section'];

	return addReportToDatabase($report);
};

function addReportFromRequest($id_origine, $request)
{
	if($id_origine != 0)
	{
		try
		{
			$report = getReport($id_origine);
			global $typesRapportsAll;
			if(
					isset($report->type)
					&& isset($request["fieldtype"])
					&& isset($typesRapportsAll[$request["fieldtype"]])
					&& ($report->type != $request["fieldtype"])
			)
				$request["fieldintitule"] = $typesRapportsAll[$request["fieldtype"]];
		}
		catch (Exception $e)
		{
			$id_origine = 0;
		}
	}
	else
	{
		if(!isReportCreatable())
			throw new Exception("Le compte ".getLogin()." n'a pas la permission de créer un rapport, veuillez contacter le bureau");
	}

	$report = createReportFromRequest($id_origine, $request);

	if(isset($report->NUMSIRHUS))
          {
            $cand = get_candidate_from_SIRHUS($data->NUMSIRHUS);
            if($cand != null)
              {
                $report->nom = $cand->nom;
                $report->prenom = $cand->prenom;
              }
          }

	$id_nouveau = addReportToDatabase($report,false);

	if(is_rapport_chercheur($report) || is_rapport_concours($report))
		updateCandidateFromRequest($request);

	return getReport($id_nouveau);
}

function createReportFromRequest($id_origine, $request)
{
	global $fieldsRapportAll;
	global $fieldsTypes;

	$row = (object) array();

	if(!isset($row->id_session))
		$row->id_session = current_session_id();

	foreach($fieldsRapportAll as  $field => $comment)
		if (isset($request["field".$field]))
		$row->$field = nl2br(trim($request["field".$field]),true);

	$row->id_origine = $id_origine;

	return $row;
}

function normalizeReport($report)
{
	global $report_prototypes;
	global $id_rapport_to_label;
	global $typesRapportsAll;
	$report = (object) $report;
	$default = array(
			 "DKEY"=>"",
			 "NUMSIRHUS"=>"",
			"id_session" => current_session_id(),
			"id_origine" => "",
			"id" => "",
			"nom" => "",
			"prenom" => "",
			"avis" => "",
			"rapport" => "",
			"prerapport" => "",
			"concours" => "",
			"statut" => "doubleaveugle",
			"rapporteur" => "",
			"rapporteur2" => "",
			"rapporteur3" => "",
	);

	foreach($default as $key => $value)
		if(!isset($report->$key))
		$report->$key = $value;

	if(!isset($report->statut))
		$report->statut = "doubleaveugle";


	if(isset($report->type))
	{
		if(!isset($report->intitule))
		  $report->intitule = (isset($typesRapportsAll[$report->type])) ? $typesRapportsAll[$report->type] : ("Type inconnu ".$report->type);
		///				if(!isset($typesRapportsAll[$report->type]))
		//foreach($typesRapportsAll as $key => $label)
		// echo ("key ".$key." label ".$label."<br>\n");

		if(isset($report_prototypes[$report->type]))
		{
			$prototype = $report_prototypes[$report->type];
			foreach($prototype as $field => $value)
				if(isset($report->$field) && $report->$field=="")
				$report->$field = $value;
		}
	}
	return $report;
}

function addReportToDatabase($report,$normalize = true)
{
	global $fieldsRapportAll;
	global $fieldsPermissions;

	if($normalize)
	 $report = normalizeReport($report);

	if(isset($report->unite))
	  try
	    {
		createUnitIfNeeded($report->unite);
	    }
	catch(Exception $e){}

	$specialRule = array("date","id","id_origine");

	$id_origine = isset($report->id_origine) ? $report->id_origine : 0;
	if($id_origine == 0)
	{
		global $empty_report;
		foreach($empty_report as $key => $value)
			if(!isset($report->$key))
			$report->$key = $value;
	}

	$level = getUserPermissionLevel();
	try
	{
		$current_report = array();
		try
		{
			$previous_report = getReport($id_origine, false);
			$current_report = getReport($id_origine);

			//echo "id_origine $id_origine current_id ".$current_report->id."<br/>";
			foreach($fieldsRapportAll as $field => $comment)
			{

				if (!in_array($field,$specialRule))
				{
					if(
					   isset($report->$field) && isset($previous_report->$field)
					   &&($previous_report->$field !== $report->$field) && isset($fieldsPermissions[$field])
					   &&  $fieldsPermissions[$field] > $level)
						throw new Exception("Vous n'avez pas les autorisations nécessaires (".$level."<".$fieldsPermissions[$field].") pour modifier le champ ".$field);
					if(isset($report->$field))
					{
						if(!isset($previous_report->$field) || $previous_report->$field !== $report->$field)
						{
							if(! is_field_editable($previous_report, $field))
								throw new Exception("Le compte ".getLogin()." n'a pas la permission de mettre à jour le champ ".$field." du rapport ".$id_origine.". Si nécessaire, veuillez contacter le bureau pour demander un changement de rapporteur.");

							if(
									isset($current_report->$field)
									&& isset($report->$field)
									&& isset($previous_report->$field)
									&& ($previous_report->$field !== $current_report->$field)
									&& ($current_report->$field !== $report->$field)
							)
							{
								global $mergeableTypes;

								global $fieldsTypes;
								$type = isset($fieldsTypes[$field]) ? $fieldsTypes[$field] : "";
								if(in_array($type, $mergeableTypes))
								{
									echo "<h2>Merge with parallel edition of field $field :</h2>'".$current_report->$field."'";
									echo "<h2>Your edition:</h2> '".$report->$field."'";
									$current_report->$field ="!!!EDITION PARALLELE!!!\n".$current_report->$field;
									$current_report->$field .= "\n* FROM '".getLogin()."':\n".$report->$field;
								}
								else
								{
									/*
									 echo "<h2>Cannot merge with parallel edition of field</h2>";
									echo "<h2>Parallel edition:</h2>".$current_report->$field;
									echo "<h2>Your edition:</h2>".$report->$field;
									echo "<h2>Erasing parallel edition...</h2>";
									*/
									$current_report->$field = $report->$field;
								}
							}
							else
							{
								$current_report->$field = $report->$field;
							}
						}
					}
				}
			}
		}
		catch(Exception $e)
		{
			if(!isReportCreatable())
				throw new Exception("Failed to add report to database<br/>".$e->getMessage());
			$current_report = $report;
		}

		$sqlfields = "";
		$sqlvalues = "";

		$specialRule = array("date","id");

		if(!isSuperUser())
		  $current_report->section = $_SESSION['filter_section'];
		else
		  $current_report->section = $report->section;

		$first = true;

		foreach($current_report as  $field => $value)
		{
			if (key_exists($field, $fieldsRapportAll) && !in_array($field,$specialRule))
			{
				$sqlfields.= ($first ? "" : ",").$field;
				$sqlvalues.=($first ? "" : ",")."\"".real_escape_string($value)."\"";
				$first = false;
			}
		}

		$sql = "INSERT INTO ".reports_db." ($sqlfields) VALUES ($sqlvalues);";
		//	echo $sql."<br/>\n";
		sql_request($sql);

		global $dbh;
		$new_id = mysqli_insert_id($dbh);

		if($id_origine != 0 && isset($current_report->id))
		{
			$current_id = $current_report->id;
			$sql = "UPDATE ".reports_db." SET id_origine=".intval($new_id);
			$sql .= " WHERE id_origine=".intval($id_origine)." OR id=".intval($new_id);
			$sql .= " OR id=".intval($current_id)." OR id_origine=".intval($current_id).";";
			//			echo $sql;
			sql_request($sql);
		}
		else
		{
			$sql = "UPDATE ".reports_db." SET id_origine=".intval($new_id)." WHERE id=".intval($new_id).";";
			//			echo $sql;
			sql_request($sql);
		}
	}
	catch(Exception $e)
	{
		throw $e;
	}

	return $new_id;
}

function next_report($id)
{
	if(!isset($_SESSION['current_id']) || !isset($_SESSION['rows_id'])  || (count($_SESSION['rows_id']) == 0))
		return -1;
	else
	{
		$c = $_SESSION['current_id'];
		$cc =  count($_SESSION['rows_id']);
		$n = ($c+ 1) % $cc;
		return $_SESSION['rows_id'][$n];
	}
}

function previous_report($id)
{
	if(!isset($_SESSION['current_id']) || !isset($_SESSION['rows_id'])  || (count($_SESSION['rows_id']) == 0))
		return -1;
	else
	{
		$c = $_SESSION['current_id'];
		$cc =  count($_SESSION['rows_id']);
		if($c <= 0) $c += $cc;
		$n = ($c - 1) % $cc;
		return $_SESSION['rows_id'][$n];
	}
}


function set_property($property,$id_origine, $value, $all_reports = false)
{
	change_report_property($id_origine, $property, $value);
	$report = getReport($id_origine);
	if($report->nom != "" && $report->prenom != "")
	{
		if($all_reports)
		{
			$sql = "UPDATE reports SET `".real_escape_string($property)."`=\"".real_escape_string($value)."\" ";
			$sql .= " WHERE `".real_escape_string($property)."`=\"\" AND nom=\"".$report->nom."\" and prenom=\"".$report->prenom."\"";
			$sql .= " AND id_session=\"".current_session()."\" AND unite=\"".$report->unite."\" AND section=\"".$report->section."\" AND type=\"".$report->type."\"";
		}
		else
		{
			$sql = "UPDATE reports SET `".real_escape_string($property)."`=\"".real_escape_string($value)."\" ";
			$sql  .= "WHERE id=".$id_origine.";";
		}
		sql_request($sql);
	}
}


/* Hugo could be optimized in one sql update request?*/
function change_statuts($new_statut)
{
	$rows = filterSortReports(getCurrentFiltersList(), getFilterValues(), getSortingValues());
	foreach($rows as $row)
		change_statut($row->id, $new_statut);
}

function updateRapportAvis($id,$avis,$rapport)
{
	$data = array("avis" => $avis, "rapport" => $rapport);
	return change_report_properties($id, $data);
}

function change_rapporteur($id, $newrapporteur)
{
	return change_report_property($id, "rapporteur", $newrapporteur);
}

function change_rapporteur2($id, $newrapporteur)
{
	return change_report_property($id, "rapporteur2", $newrapporteur);
}

function change_statut($id, $newstatut)
{
	return change_report_property($id, "statut", $newstatut);
}

function change_report_property($id_origine, $property_name, $newvalue)
{
	$id = getIDOrigine($id_origine);
	$sql = "UPDATE `reports` SET ". real_escape_string($property_name)."=\"".real_escape_string($newvalue)."\" WHERE id=\"".$id."\"";
	sql_request($sql);
	return $id_origine;
}

function change_report_properties($id_origine, $data)
{
	$row = NULL;
	$request = array();
	try
	{
		$report = getReport($id_origine);
		//		echo "Found report with id ". $id_origine."<br/>";
	}
	catch (Exception $e)
	{
		echo "Could not find report with id ". $id_origine.", trying to create new report...<br/>";
		$id_origine = 0;
	}

	if($id_origine != 0)
	{
		foreach($report as $key => $value)
		{
			if(isset($data[$key]))
				$request["field".$key] = $data[$key];
		}
	}
	else
	{
		foreach($data as $key => $value)
		{
			$request["field".$key] = $data[$key];
		}
	}
	$result = addReportFromRequest($id_origine,$request);
	return $result;
}

function get_current_selection()
{
	return filterSortReports(getCurrentFiltersList(), getFilterValues(), getSortingValues());
}

function getVirginReports($rapporteur)
{
	$filter_values = array('rapporteur' => $rapporteur->login, 'avis1' => '');
	$liste1 =  filterSortReports(getCurrentFiltersList(), $filter_values,getSortingValues());

	$filter_values = array('rapporteur2' => $rapporteur->login, 'avis2' => '');
	$liste2 =  filterSortReports(getCurrentFiltersList(), $filter_values,getSortingValues());

	$filter_values = array('rapporteur3' => $rapporteur->login, 'avis3' => '');
	$liste3 =  filterSortReports(getCurrentFiltersList(), $filter_values,getSortingValues());

	return array_merge($liste1,$liste2, $liste3);
}

function getRapporteurReports($login)
{
	return filterSortReports(getCurrentFiltersList(), array("rapporteur" => $login, "id_session=" => current_session_id()) ,getSortingValues() );
}

function getTodoReports($login)
{
	return filterSortReports(getCurrentFiltersList(), array("avancement" => "todo", rapporteur => $login, "id_session=" => current_session_id()) ,getSortingValues() );
}

function find_somebody_reports($candidate,$eval_type = "")
{
	if($eval_type == "")
		return  filterSortReports(array("nom"=>"","prenom" => ""), array("nom"=>$candidate->nom,"prenom" => $candidate->prenom), array("id_session"=>"+", "type"=>"+"));
	else
		return  filterSortReports(array("nom"=>"","prenom" => "","type"=>""), array("nom"=>$candidate->nom,"prenom" => $candidate->prenom,"type"=>""), array("id_session"=>"+", "type"=>"+"));
}

function find_unit_reports($code)
{
	if($code == "")
		return array();

	$sql = "SELECT * from ".reports_db. " WHERE id=id_origine AND statut!=\"supprime\"";
	$sql .= ' AND unite="'.$code.'" AND section="'.currentSection().'" ORDER BY id ASC';

	$result=sql_request($sql);

	if($result == false)
		throw new Exception("Echec de l'execution de la requete <br/>".$sql."<br/>");

	$rows = array();
	while ($row = mysqli_fetch_object($result))
		$rows[] = $row;

	return $rows;
}

function find_people_reports($nom, $prenom)
{
	if($nom == "" && $prenom == "")
		return array();

	$sql = "SELECT * from ".reports_db. " WHERE id=id_origine AND statut!=\"supprime\"";
	$sql .= ' AND nom="'.$nom.'" AND prenom="'.$prenom.'" AND section="'.currentSection().'" ORDER BY id ASC';

	$result=sql_request($sql);

	if($result == false)
		throw new Exception("Echec de l'execution de la requete <br/>".$sql."<br/>");

	$rows = array();
	while ($row = mysqli_fetch_object($result))
		$rows[] = $row;

	return $rows;
}

function update_report_from_concours($id_origine,$concours,$login)
{
	global $fieldsRapportsCandidat;
	global $fieldsRapportsCandidat1;
	global $fieldsRapportsCandidat2;

	$report = getReport($id_origine);

	$filters = array("concours"=>"","nom"=>"","prenom"=>"","type"=>"");
	$filtersvalues = array("concours" => $concours,"nom" => $report->nom,"prenom" => $report->prenom,"type"=>REPORT_CANDIDATURE);
	$reports = filterSortReports($filters,$filtersvalues);
	if(count($reports) < 1)
		throw new Exception("Cannot update report ".$id_origine." from concours ".$concours." : no such report for candidate ".$report->nom);
	$report2 = $reports[0];

	$fields = array();
	if($login == $report->rapporteur)
		$fields = $fieldsRapportsCandidat1;
	else if ($login == $report->rapporteur2)
		$fields = $fieldsRapportsCandidat2;
	else if(isSecretaire($login))
		$fields = $fieldsRapportsCandidat;

	$fields[] = "type";
	$fields[] = "nom";
	$fields[] = "prenom";


	$data = array();
	foreach($fields as $field)
		$data[$field] = $report2->$field;

	return change_report_properties($id_origine,$data);

}

function listOfAllVirginReports()
{
	$result = "";
	$users = listUsers();
	foreach($users as $rapporteur)
	{
		$reports  = getVirginReports($rapporteur);
		if(count($reports) > 0)
		{
			$result .= "<br/><B>Rapporteur \"".$rapporteur->description."\" (". $rapporteur->email.") :</B><br/>";
			foreach($reports as $report)
				$result .= reportShortSummary($report)."<br/>";
		}
	}
	return $result;
}

function is_in_conflict_efficient($row, $login)
{
	return (strpos($row->people_conflits,$login)!== false);
}

function is_field_editable($row, $fieldId)
{
	$statut = isset($row->statut) ? $row->statut : "rapport";
	$eval_type = isset($row->type) ? $row->type : "";
	global $typesRapportToFields;
	global $fieldsPeople;

	//certains champs ne sont pas voués à etre edites
	global $nonEditableFieldsTypes;
	if(in_array($fieldId, $nonEditableFieldsTypes))
		return false;

	//le secretaire/ACN peut changer le statut, seul le secrétaire/president peut dépublier
	if($fieldId == "statut" && ($statut != "publie" || !isACN()))
		return isSecretaire();

	//une fois le rapport transmis, plus rien n'est publiable
	if($statut == "publie")
		return false;

	//une fois les avis tranmis, seul le rapport et les rapporteurs sont editables et l'ACN n'a également accès qu'à ces éléments en édition
	if((isACN() || $statut == "avistransmis") &&  ! ($fieldId == "rapport" || $fieldId == 'rapporteur' || $fieldId == 'rapporteur2' || $fieldId == 'rapporteur3'))
		return false;			
	
	//ACN can not see only certain fields
	if(isACN())
	{
		global $fieldsEditableACN;
		return in_array($fieldId, $fieldsEditableACN);
	}
	
	if($fieldId == "type" || $fieldId == "conflits")
		return isSecretaire();
	
	if($fieldId == 'rapporteur' || $fieldId == 'rapporteur2' || $fieldId == 'rapporteur3')
		return isBureauUser();

	if(isSecretaire())
		return true;

	//le bureau peut éditer les infos nominatives
	if(isBureauUser() && in_array($fieldId, $fieldsPeople) )
		return true;

	$login = getLogin();

	$is_rapp1 = isset($row->rapporteur) && ($login == $row->rapporteur);
	$is_rapp2 = isset($row->rapporteur2) && ($login == $row->rapporteur2);
	$is_rapp3 = isset($row->rapporteur3) && ($login == $row->rapporteur3);

	/*			'doubleaveugle'=>'Edition Prérapports Double Aveugle',
			 'edition' => "Edition Prérapports et Rapports",
			 'avistransmis'=>"Publication des Avis",
			 'publie'=>"Publication des Rapports",
			 'audition'=>"Audition"
*/
	if(($is_rapp1 || $is_rapp2 || $is_rapp3) && $fieldId == "rapport")
		return true;

	if(isset($row->statut) && ($row->statut == "audition"))
	{
		if(isset($row->sousjury) && isPresidentSousJury($row->sousjury))
			return true;

		if($fieldId == "fichiers")
			return true;

		if( $is_rapp1  && ($fieldId == "avissousjury" || $fieldId=="audition"))
			return true;
	}

	if(isset($row->type) && $row->type == REPORT_CANDIDATURE && isset($row->avis) && is_numeric($row->avis) && $fieldId =="rapport" && ($is_rapp1 || $is_rapp2 || $is_rapp3))
		return true;

	if(!$is_rapp1 && !$is_rapp2 && !$is_rapp3 && !isSecretaire())
		return false;

	global $fieldsIndividual;
	global $fieldsIndividualAll;

	//individual fields are always editable
	if(isset($fieldsIndividualAll[$fieldId]))
		return (isSecretaire() || $is_rapp1 || $is_rapp2 || $is_rapp3);

	$fieldsIndividual0 = $typesRapportToFields[$eval_type][1];
	$fieldsIndividual1 = $typesRapportToFields[$eval_type][2];
	$fieldsIndividual2 = $typesRapportToFields[$eval_type][3];
	$fieldsIndividual3 = $typesRapportToFields[$eval_type][4];
	$f0 = in_array($fieldId,$fieldsIndividual0);
	$f1 = in_array($fieldId,$fieldsIndividual1);
	$f2 = in_array($fieldId,$fieldsIndividual2);
	$f3 = in_array($fieldId,$fieldsIndividual3);

	if(is_rapport_concours($row))
	{
		global $fieldsCandidat;
		$f = in_array($fieldId,$fieldsCandidat);
		return (isSecretaire() && ($f || $f0 || $f1 || $f2 || $f3)) || ( $is_rapp1 && ($f1 || $f) )  || ($is_rapp2 && ($f2 || $f)) || ($is_rapp3 && ($f3 || $f) );
	}

	if(is_rapport_unite($row))
	{
		global $fieldsUnites;
		$result = in_array($fieldId,$fieldsUnites) &&
		(isSecretaire()
		 || ($fieldId == "ecole" && ($is_rapp1 || $is_rapp2 || $is_rapp3))
				|| ($fieldId == "prerapport" && $is_rapp1)
				|| ($fieldId == "prerapport2" && $is_rapp2)
				|| ($fieldId == "prerapport3" && $is_rapp3)
				|| ($fieldId == "avis1" && $is_rapp1)
				|| ($fieldId == "avis2" && $is_rapp2)
				|| ($fieldId == "avis3" && $is_rapp3)
		);
		return $result;
	}

	if(is_rapport_chercheur($row))
	{
		global $fieldsChercheursAll;
		$f = in_array($fieldId,$fieldsChercheursAll);
		return
		(isSecretaire() &&
				($f || $f0 || $f1 || $f2 || $f3))
				|| ( $is_rapp1 && ($f1 || $f) )
		  || ($is_rapp2 && ($f2 || $f) )
		  || ($is_rapp3 && ($f3 || $f) )
		      || ($fieldId == "ecole")
		  ;
	}

	global $fieldsGeneric;
	return in_array($fieldId,$fieldsGeneric);
}

function is_field_visible($row, $fieldId)
{
	global $typesRapportToFields;
	global $alwaysVisibleFieldsTypes;

	global $nonVisibleFieldsTypes;
	if(in_array($fieldId, $nonVisibleFieldsTypes))
		return false;

	if(in_array($fieldId, $alwaysVisibleFieldsTypes))
		return true;

	
	//ACN can not see only certain fields
	if(isACN())
	{
		global $fieldsRapportACN;
		return in_array($fieldId, $fieldsRapportACN);
	}	
	
	if($fieldId == "type" && !isSecretaire())
		return false;

	//editable info is always visible
	if(is_field_editable($row, $fieldId))
		return true;

	//when non editable non existing fields are not visible
	if(!isset($row->$fieldId))
		return false;

	//nothing to display -> nothing displayed
	if($row->$fieldId == '')
		return false;

	//during prerapport edition we do not want rapporteurs to see each other reports
	//only editable info is visible
	$login = getLogin();
	$is_rapp1 = isset($row->rapporteur) && ($login == $row->rapporteur);
	$is_rapp2 = isset($row->rapporteur2) && ($login == $row->rapporteur2);
	$is_rapp3 = isset($row->rapporteur3) && ($login == $row->rapporteur3);

	if(isset($row->statut) && ($row->statut == "doubleaveugle") && ($is_rapp1 || $is_rapp2 || $is_rapp3))
		return false;

	return true;
}

function get_editable_fields($row)
{
	global $fieldsAll;
	$result = array();
	foreach($fieldsAll as $field => $data)
		if(is_field_editable($row,$field))
		$result[] = $field;
	return $result;
}

function get_readable_fields($row)
{
	global $fieldsAll;
	$result = array();
	foreach($fieldsAll as $field => $data)
		if(is_field_visible($row,$field))
		$result[] = $field;
	return $result;
}
function migrate_to_avis_codes()
{

		foreach(array("avis","avis1","avis2","avis3") as $field)
			  {
			    echo "Updating classement<br/>";
			$sql = "UPDATE `".reports_db."` SET `".$field."`=CONCAT(\"c\",".$field.") WHERE ".$field." REGEXP '[0-9]+';";
			sql_request($sql);
			echo $sql;
			  }


  $mig = array(
	       "tresfavorable" => avis_tres_favorable,
	       "favorable" => avis_favorable,
	       "defavorable" => avis_defavorable,
	       "reserve" => avis_reserve,
	       "alerte" => avis_alerte,
	       "differe" => avis_differe,
	       "sansavis" => avis_pas_davis,
	       "oui" => avis_oui,
	       "non" => avis_non,
	       "nonclasses" => avis_non_classe,
	       "adiscuter"=> avis_adiscuter,
	       "desistement"=>avis_desistement,
	       "nonconcur"=>avis_nonconcur,
	       "nonauditionne"=>avis_nonauditionne,
	       "oral"=>avis_oral,
	       "classe"=>avis_estclasse
	       );

		foreach($mig as $pref => $id)
		{
		  foreach(array("avis","avis1","avis2","avis3") as $field)
			  {
			    echo "Updating field ".$field. " avis ".$pref." => ".$id."<br/>";
			$sql = "UPDATE `".reports_db."` SET `".$field."`=\"".$id."\" WHERE `".$field."`=\"".$pref."\";";
			sql_request($sql);
			  }
		}



}

function migrate_to_eval_codes()
{
	if(isSuperUser())
	{
		$mig = array(
				"Suivi-PostEvalua" => 6009,
				"Renouvellement-G"=> 8025,
				"Reexamen"=>6008,"EvalMiVague"=>6005,
				"Delegation"=>7778, "DEChercheur"=>7779,
				"Creation-GDR"=>8015,"Changement d'aff"=>7012,
				"Ch-section"=>"6515","Candidature"=>7777,
				"Generique"=>"7780","DEChercheur"=>7779,
				"EvalVague"=>"6005","Emeritat"=>7017,
				"ChgtSection"=>6515, "Renouvellement"=>8020,
				"Association"=>8021
		);

		foreach($mig as $pref => $id)
		{
			$sql = "UPDATE `".reports_db."` SET `type`=\"".$id."\" WHERE `type`=\"".$pref."\";";
			sql_request($sql);
		}


		echo "Migrating to eval codes <br/>";
		$sql = "UPDATE `".reports_db."` SET `type`=\"6515\" WHERE `type`=\"Changement-section\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`=\"ChgtDir\" WHERE `type`=\"ChgtDir-Adjoint\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`=\"8101\" WHERE `type`=\"Changement-Directeur-Adjoint\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`=\"8101\" WHERE `type`=\"Changement-Directeur\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`=\"8101\" WHERE `type`=\"ChgtDir\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`=\"8515\" WHERE `type`=\"Ecole\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`=\"6005\" WHERE `type`=\"Evaluation-MiVague\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`=\"6005\" WHERE `type`=\"Evaluation-Vague\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `intitule`= `ecole` WHERE `intitule`=\"\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`= \"6005\" WHERE `intitule`=\"Evaluation de chaire\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`= \"6525\" WHERE `intitule`=\"Evaluation permanente par une deuxième section\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`= \"6009\" WHERE `intitule`=\"Suivi post-évaluation\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`= \"6525\" WHERE `intitule`=\"Evaluation permanente par une 2ème section ou CID\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`= \"6520\" WHERE `intitule`=\"Renouvellement de mise a disposition\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`= \"6005\" WHERE `intitule`=\"Rapport sur chercheur\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`= \"7006\" WHERE `type`=\"MedailleArgent\";";
		sql_request($sql);
		$sql = "UPDATE `".reports_db."` SET `type`= \"7005\" WHERE `type`=\"MedailleBronze\";";
		sql_request($sql);


		$sql = "SELECT * FROM report_types WHERE code_marmotte=\"\";";
		$result = sql_request($sql);
		while ($row = mysqli_fetch_object($result))
		{
			$sql = "UPDATE `".reports_db."` SET `type`=\"".$row->id."\" WHERE `type`=\"".$row->code_marmotte."\";";
			sql_request($sql);
		}

		global $id_rapport_to_label;
		foreach($id_rapport_to_label as $id => $data)
		{
			if($id != 9999)
				$sql = "UPDATE `".reports_db."` SET `intitule`=\"".$data."\" WHERE `type`=\"".$id."\" AND intitule=\"\";";
			else
				$sql = "UPDATE `".reports_db."` SET `intitule`=`ecole` WHERE `type`=\"9999\";";
			sql_request($sql);
		}

	}



}

function is_rapport_chercheur($row)
{
	global $report_types_to_class;
	return (
			isset($row->type)
			&& isset($report_types_to_class[$row->type])
			&& (
					$report_types_to_class[$row->type] == REPORT_CLASS_CHERCHEUR
					|| $report_types_to_class[$row->type] == REPORT_CLASS_DELEGATION
			)
	);
}

function is_rapport_concours($row)
{
	global $report_types_to_class;
	return (isset($row->type) && isset($report_types_to_class[$row->type]) && ($report_types_to_class[$row->type] == REPORT_CLASS_CONCOURS));
}

function is_concours_type($type)
{
	global $report_types_to_class;
	return ( isset($report_types_to_class[$type]) && ($report_types_to_class[$type] == REPORT_CLASS_CONCOURS));
}

function is_rapport_unite($row)
{
	global $report_types_to_class;
	return (isset($row->type) && is_unite_type($row->type));
}

function is_unite_type($type)
{
	global $report_types_to_class;
	return (isset($report_types_to_class[$type]) && ($report_types_to_class[$type] == REPORT_CLASS_UNIT));
}
/*
function is_ecole_type($type)
{
  return $type == REPORT_ECOLE;
  }*/

function is_promotion_type($type)
{
  global $typesRapportsPromotion;
  return in_array($type, $typesRapportsPromotion);
}

function is_eval_type($type)
{
	return ($type == REPORT_EVAL) || ($type == REPORT_EVAL_RE);
}

function get_current_report_types()
{
	$types = array();
	if(is_current_session_concours())
	{
		global $typesRapportsConcours;
		return $typesRapportsConcours;
	}
	else if(is_current_session_delegation())
	{
		return  array('Delegation'=>'Délégation');
	}
	else
	{
		global $typesRapportsSession;
		return $typesRapportsSession;
	}
}

function inject_new_reports_from_dsi()
{
	$sql = "SELECT * FROM dsi.evaluationdoc WHERE numsirhus NOT IN SELECT numsirhus FROM dsi.evaluationdoc;";

	$result = sql_request($sql);
	$sessions = get_all_sessions();

	$added = array();
	while($row = mysqli_fetch_object($result))
	{
		if(!in_array($row->numsirhus,$added))
		{
			$added[] = $row->numsirhus;
			$session = $row->lib_session.$row->annee;
			$section = $row->code_section;
			if( !isset($sessions[$section]) || !in_array($session, $sessions[$section]))
			{
				createSession($row->lib_session, $row->annee, $section);
				$sessions[$section][] = $session;
			}
			$report = array(
					"section" => $section,
					"nom" => $nom,
					"prenom" => $prenom,
					"rapporteur" => $row->rap1,
					"rapporteur2" => $row->rap2,
					"rapporteur3" => $row->rap3,
					"type" => $type_eval
			);
			//		addReport($report);
		}
	}
}
?>