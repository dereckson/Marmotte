<?php 

require_once('config.inc.php');
require_once('manage_sessions.inc.php');
require_once('manage_files.php');


function normalizeCandidat($data)
{
	$data2 = (object) $data;

	if(!isset($data2->nom))
		$data2->nom = "";
	if(!isset($data2->prenom))
		$data2->prenom = "";

	return $data2;
}

function is_classe($report)
{
  return $report->avis != "" && $report->avis[0] == 'c';
}

function is_auditionne($report)
{
  global $avis_lettre;
  return is_classe($report) || $report->avis==avis_oral || $report->avis==avis_non_classe || isset($avis_lettre[$report->avis]);
}

function is_auditionneCR($report)
{
	global $concours_ouverts;
	return (isset($concours_ouverts[$report->concours]) && substr($concours_ouverts[$report->concours],0,2)=="CR")
	&&(is_classe($report) || $report->avis=="oral" || $report->avis=="nonclasse");
}


function is_in_conflict($login, $candidat)
{
	//	echo "conflits '".$candidat->conflits."' login '".$login."'";
	return isset($candidat->conflits) && (strpos($candidat->conflits,$login) !== false);
}

function add_conflit_to_report($login, $id_origine)
{


	$report = getReport($id_origine);
	$row = normalizeReport($report);
	$candidat = get_or_create_candidate($row);

	$conflits = isset($candidat->conflits) ? $candidat->conflits : "";
	//	if(strpos($conflits,$login) === false)
	{
			$conflits .= ";".$login;
			if(isset($candidat->nom) && isset($candidat->prenom) && $candidat->nom != "")
				$candidat->conflits = $conflits;
			//			echo $candidat->conflits;
			updateCandidateFromData($candidat,$candidat->concoursid);
	}
}

function updateCandidateFromRequest($request, $concoursid = "")
{
	global $fieldsIndividualDB;
	$data = (object) array();
	foreach($fieldsIndividualDB as  $field => $value)
	  {
		if (isset($request["field".$field]))
		$data->$field = nl2br(trim($request["field".$field]),true);
	  }
	updateCandidateFromData($data,$concoursid);
}

function updateCandidateFromData($data, $concoursid="")
{
	global $fieldsIndividualDB;


	$candidate = get_or_create_candidate($data );

	if(!isset($candidate->nom) || $candidate->nom == "")
	  return ;

	$sqlcore = "";

	$first = true;
	foreach($data as  $field => $value)
	{
		if(
		   key_exists($field, $fieldsIndividualDB)
		   && ($field != "nom") && ($field != "prenom")
		   )
		{
			$sqlcore.=$first ? "" : ",";
			$sqlcore.=$field.'="'.real_escape_string($value).'" ';
			$first = false;
		}
	}

	if(!isSuperUser() && isset($data->section) && ($data->section != currentSection()))
		throw new Exception("Le compte ".$login." n'a pas la permission de modifier un candidat  pour une autre section que la sienne.");


	if($sqlcore != "") {
	if($concoursid != "") {
	  $sql = "UPDATE ".people_db." SET ".$sqlcore." WHERE concoursid=\"".$concoursid."\" AND section=\"".currentSection()."\" ;";
	} else {
	  $sql = "UPDATE ".people_db." SET ".$sqlcore." WHERE nom=\"".$data->nom."\" AND prenom=\"".$data->prenom."\" AND concoursid='' AND section=\"".currentSection()."\" ;";
	}
	//	echo $sql; rr();
	sql_request($sql);
	}
}

function getAllCandidates()
{
	$sql = "SELECT * FROM ".people_db." WHERE section=\"".currentSection()."\" ;";
	$result=sql_request($sql);
	if($result == false)
		throw new Exception("Failed to process sql query ".$sql);
	$rows = array();

	while ($row = mysqli_fetch_object($result))
		$rows[] = $row;

	return $rows;
}

function  set_people_property($property,$numsirhus, $value)
{
  $sql = "UPDATE ".people_db." SET ".$property."=\"".$value."\" WHERE NUMSIRHUS=\"".$numsirhus."\";";
  sql_request($sql);
  echo $sql;
  //  throw new Exception($sql);
}


function add_candidate_to_database($data,$section="")
{
	if($section == "")
		$section = currentSection();

	global $fieldsIndividualDB;
	$sqlvalues = "";
	$sqlfields = "";
	$first = true;

	global $empty_individual;
	foreach($fieldsIndividualDB as $field => $desc)
		if($field != "fichiers")
		{
			$sqlfields .= ($first ? "" : ",") ."`".$field."`";
			$sqlvalues .= ($first ? "" : ",");
			$sqlvalues .= '"'.
			  real_escape_string((isset($data->$field) ? $data->$field : ( isset($empty_individual[$field]) ? $empty_individual[$field] : "") ));
			$sqlvalues .= '"';
			$first = false;
		}

		$sqlfields .= ",section";
		$sqlvalues .= ",\"".$section."\"";
		$sqlfields .= ",NUMSIRHUS";
		$sqlvalues .= ",".(isset($data->NUMSIRHUS) ? ("\"".$data->NUMSIRHUS ."\"") : "\"\"");

		$sql = "INSERT INTO ".people_db." ($sqlfields) VALUES ($sqlvalues);";
		sql_request($sql);

		$sql2 = 'SELECT * FROM '.people_db.' WHERE `nom`="'.$data->nom.'" AND `prenom`="'.$data->prenom.'" AND section="'.$section.'";';
		$result = sql_request($sql2);
		$candidate = mysqli_fetch_object($result);

		if($candidate == false)
			throw new Exception("Failed to add candidate with request <br/>".$sql2);

		return $candidate;
}

function get_or_create_candidate($data)
{

  $people = false;
  $data = normalizeCandidat($data);
  $section = currentSection();

  //  echo $data->concoursid;
  //  echo "ff";
  //echo $data->peopleid;
  //  rr();

  if(isset($data->concoursid) && $data->concoursid!="") {
    $sql = "SELECT * FROM ".people_db.' WHERE concoursid="'.$data->concoursid.'" AND section="'.$section.'"';
    $result = sql_request($sql);
    $people = mysqli_fetch_object($result);
  }
  if($people == false && isset($data->peopleid) && $data->peopleid != 0) {
    $sql = "SELECT * FROM ".people_db.' WHERE id="'.$data->peopleid.'" AND section="'.$section.'"';
    $result = sql_request($sql);
    $people = mysqli_fetch_object($result);
  } 
  if($people == false) {
	$data->nom = ucwords(strtolower($data->nom));
	$data->prenom = ucwords(strtolower($data->prenom));
	$cid = isset($data->concoursid) ? $data->concoursid : "";
	$sql = "SELECT * FROM ".people_db.' WHERE concoursid="'.$cid.'" AND nom="'.$data->nom.'" AND prenom="'.$data->prenom.'" AND section="'.$section.'" ;';
	$result = sql_request($sql);
	$people = mysqli_fetch_object($result);
  }

	try
	{
		if($people == false)
		{
			add_candidate_to_database($data,$section);
			$result = sql_request($sql);
			$people = mysqli_fetch_object($result);
			if($people == false)
				throw new Exception("Failed to find candidate previously added<br/>".$sql);
		}
		else if(isset($data->NUMSIRHUS) && $data->NUMSIRHUS != "")
		  {
		$people->NUMSIRHUS = $data->NUMSIRHUS;
		$cand = get_candidate_from_SIRHUS($data->NUMSIRHUS);
		if($cand != null)
		  {
		    global $fieldsDSIChercheurs;
		    global $refposition;
		    $people->infos_evaluation = "";
		    foreach($fieldsDSIChercheurs as $key => $data)
		      {
			    if(is_array($data))
			      {
				$loc = "";
				foreach($data as $key2 => $data2)
				  {
				    if(!isset($cand->$key2) || $cand->$key2 == "") break;
				    if($key2 == "codeposition" && isset($refposition[$cand->$key2]))
				      $loc.= $data2." ".$refposition[$cand->$key2]." ";
				    else
				      $loc.= $data2." ".$cand->$key2." ";
				  }
				if($loc != "")
				  $people->infos_evaluation.= $loc."<br/>";
			      }
			    else if(isset($cand->$key) && $cand->$key != "")
			      $people->infos_evaluation.= $data." ".$cand->$key."<br/>";
		      }
		    $people->nom = $cand->nom;
		    $people->prenom = $cand->prenom;
		  }
	      }

		return normalizeCandidat($people);
	}
	catch(Exception $exc)
	{
		throw new Exception("Failed to add candidate from report:<br/>".$exc->getMessage());
	}
}


function get_candidate_from_SIRHUS($sirhus)
{
	$sql = "SELECT * FROM ".dsidbname.".".dsi_people_db." WHERE numsirhus=\"".$sirhus."\"";
	$res = sql_request($sql);
	while($row = mysqli_fetch_object($res))
		return $row;
	return null;
}

function get_candidate_from_concoursid($user_id)
{
  $sql = "SELECT * FROM ".dsidbname.".".celcc_candidats." dsi LEFT JOIN ".marmottedbname.".people marmotte ";
  $sql .= "ON marmotte.concoursid=dsi.user_id WHERE dsi.user_id=\"".$user_id."\" AND marmotte.section=\"".currentSection()."\";";
	$res = sql_request($sql);
	//	echo $sql."<br/>";
	while($row = mysqli_fetch_object($res))
	  {
	    //on récupère tous les concours du candidat
	    $sql = "SELECT num_conc FROM ".dsidbname.".".celcc_candidatures." WHERE user_id=\"".$row->user_id."\"";
	    $result2 = sql_request($sql);
	    $all_concours = "";
	    while($row2 = mysqli_fetch_object($result2))
	      {
		$all_concours.=$row2->num_conc." ";
	      }
	    $row->concourspresentes = $all_concours;
	    //    $row->concoursid = $row->user_id;
	    
	    $row->infos_celcc = "<b>".$row->diplome."</b> ".$row->date_dip." ".$row->lieu_dip."<br/>";
	    if($row->lieu_habil_rech != "")
	      $row->infos_celcc .= "<b>HDR</b> ".$row->dat_habil_rech." ".$row->lieu_habil_rech."<br/>";
	    if($row->nb_an_rech != "")
	      $row->infos_celcc .= "<b>Années d'exercice de la recherche</b> ".$row->nb_an_rech."<br/>";
	    if($row->sitact_frce == "N/A") $row->sitact_frce = "?";
	    $row->infos_celcc .= "<b>Situation</b> ".$row->sitact_frce." ";
	    if($row->epst_frce != "N/A")
	      $row->infos_celcc .= $row->epst_frce." contrat: ".$row->type_epst_frce." ";
	    if($row->type_ensup_frce != "N/A")
	      $row->infos_celcc .= " (".$row->type_ensup_frce.")";
	    if($row->type_ensec_frce != "N/A")
	      $row->infos_celcc .= " (".$row->type_ensec_frce.")";
	    if($row->grade_epst_frce != "N/A")
	      {
		$row->grade = $row->grade_epst_frce;
		$row->infos_celcc .= $row->grade_epst_frce." depuis ".$row->date_grad_epst_frce." ";
	      }
	    $row->infos_celcc .= "<br/>";
	    $row->infos_celcc .= "<b>Concours présentés</b> ".$row->concourspresentes."<br/>";
	    $row->infos_celcc .= "<b>Origine candidature</b> ".$row->origine." (#".$row->user_id.")<br/>";
	    //	    $row->infos_celcc .= "<b>Voeux affectation</b> ".$row->rappel_int_labo."<br/>";
	    
	    return $row;
	  }
	return null;
}

function norm_name($nom)
{
	$nom = replace_accents($nom);
	return strtoupper(str_replace(array(" ","'","-"), array("_","_","_"),$nom));
}



?>
