<?php

require_once("manage_users.inc.php");
require_once("manage_sessions.inc.php");

function synchronizeEmailsUpdates()
{
	if(!isSecretaire())
		throw new Exception("Vous n'avez pas les droits sffisnats pour cette opération");

	$result = "<B>Synchronisation des changements d'emails</B><br/>\n";

	$users = listUsers(true);

	$changed = false;
	
	/* changements d'emails */
	foreach($users as $user)
	{
		$fields = array("section_numchaire", "CID_numchaire");
		foreach($fields as $field)
		{
			if($user->$field != "")
			{
				$sql = "SELECT * FROM ".dsidbname.".".dsi_users_db;
				$sql .= " WHERE `mailpro`!=\"".$user->login."\" AND `".$field."` =\"".$user->$field ."\" ";
				if (isSuperUser())
					$sql .= ";";
				else
					$sql .= " AND ( `CID_code`=\"".currentSection()."\" OR `section_code`=\"".currentSection()."\");";
				$res = sql_request($sql);
				while ($row = mysqli_fetch_object($res))
				{
					$changed = true;
					$result .= "Migation des dossers de '".$user->login."' vers '".$row->mailpro."' pour le numéro de chaire '".$user->$field."'<br/>";
					mergeUsers($user->login, $row->mailpro);
					$sql = "UPDATE ".users_db." SET `login`='".$row->mailpro."', `email`='".$row->mailpro."' WHERE `".$field."`='".$row->$field."';";
					sql_request($sql);
				}
			}
		}
	}
	if(!$changed)
		$result .= "Aucun email n'a été mis à jour.<br/>";
	return $result;
}


function synchronizeWithDsiMembers()
{
	$result = "";
	if(!isSecretaire())
		throw new Exception("Vous n'avez pas les droits sffisnats pour cette opération");
	$users = listUsers();

//	$result .= "La base marmotte contient ".count($users)." membres.<br/>\n";

	$result .= synchronizeEmailsUpdates();
	$result .= "<B>Synchronisation des membres de la section</B><br/>\n";
	
	if (isSuperUser())
		$sql = "SELECT * FROM ".dsidbname.".".dsi_users_db." WHERE 1;";
	else
		$sql = "SELECT * FROM ".dsidbname.".".dsi_users_db." WHERE CID_code=\"".currentSection()."\" OR section_code=\"".currentSection()."\";";

	$res = sql_request($sql);
//	$result .= "La base dsi contient ". mysqli_num_rows($res)." membres.<br/>\n";
	
	$changed = false;
	$added = false;
	
	while ($row = mysqli_fetch_object($res))
	{
		$login = $row->mailpro;
		$fields = array("section_numchaire","CID_numchaire","section_code","CID_code","section_role_code", "CID_role_code");
		try
		{
			$user = getUserByLogin($login, true);
			if($user != null)
			{
				foreach($fields as $field)
				{
					if($row->$field != $user->$field)
					{
						$changed = true;
						$result .= "Mise à jour du champ '".$field."' du membre '".$login."' de '". $user->$field."' vers '".$row->$field."'<br/>\n";
						$sql = "UPDATE ".users_db." SET `".$field."`='".$row->$field."' WHERE `login`='".$login."';";
						sql_request($sql);
					}
				}
			}
			else
			{
				$result .= "Ajout du compte ".$login." à la base marmotte.<br/>";
				$sql = "INSERT INTO ".users_db." (login,sections,permissions,section_code,section_role_code,CID_code,CID_role_code,section_numchaire,CID_numchaire, passHash,description,email,tel) ";
				$sql .= "VALUES ('";
				$sql .= real_escape_string($login)."','','0','".$row->section_code."','".$row->section_role_code."','".$row->CID_code."','".$row->CID_role_code."','".$row->section_numchaire."','".$row->CID_numchaire."','','".real_escape_string($row->nom." ".$row->prenom)."','".$login."','');";
				sql_request($sql);
			}
		}
		catch(Exception $exc)
		{
			$result .= "Erreur: ".$exc->getMessage()."<br/>\n";
		}
	}
	if(!$added)
		$result .= "Aucun utilisateur n'a été ajouté à la base<br/>";
	if(!$changed)
		$result .= "Aucune donnée utilisateur n'a été mise à jour<br/>";
	unset($_SESSION['all_users']);

	return $result;
}

function synchronizeSessions()
{
	$changed = false;
	$answer = "<B>Synchronization des sessions </B><br/>\n";
	$sql = "SELECT DISTINCT LIB_SESSION,ANNEE FROM ".dsidbname.".".dsi_evaluation_db;
	$sql.=" WHERE `CODE_SECTION` =\"".currentSection()."\" OR `CODE_SECTION_2`=\"".currentSection()."\" OR `CODE_SECTION_EXCPT`=\"".currentSection()."\";";
	$res = sql_request($sql);
	$sessions = get_all_sessions(currentSection());
	while($row = mysqli_fetch_object($res))
	{
		$session = $row->LIB_SESSION.$row->ANNEE;
		if( ! in_array($session, $sessions) )
		{
			$changed = true;
			$answer .= "Création de la session ".$session. ".<br/>";
			createSession($row->LIB_SESSION, $row->ANNEE, currentSection());
		}
	}
	if(!$changed)
		$answer .= "Aucune session n'a été ajoutée.<br/>";
	return $answer;
}

function synchronizePeople()
{
	$answer = "<B>Synchronisation des numéros SIRHUS de chercheurs</B><br/>\n";
	$sql =  "UPDATE ".people_db." marmotte JOIN ".dsidbname.".".dsi_people_db." dsi ";
	$sql .= " ON marmotte.nom=dsi.nom AND marmotte.prenom=dsi.prenom";
	$sql .= " SET marmotte.NUMSIRHUS=dsi.numsirhus";
	$sql .= " WHERE marmotte.NUMSIRHUS=\"\";";
	$res = sql_request($sql);
	global $dbh;
	$num = mysqli_affected_rows($dbh);
	if($num > 0)
		$answer = "Mise a jour de ".$num." numéros SIRHUS<br/>";
	else
		$answer .= "Aucune numéro SIRHUS n'a été mis à jour.<br/>";
	return 	$answer;
}
//id_unite
function synchronizePeopleReports()
{
	$answer = "<B>Synchronisation des rapports chercheurs</B><br/>\n";
	$sql = "SELECT * FROM ".dsidbname.".".dsi_evaluation_db;
	$sql.=" WHERE (DKEY NOT IN (SELECT DKEY FROM ".marmottedbname.".".reports_db."  WHERE DKEY != \"\")) ";
	$sql .=" AND (`CODE_SECTION` =\"".currentSection()."\" OR `CODE_SECTION_2`=\"".currentSection()."\" OR `CODE_SECTION_EXCPT`=\"".currentSection()."\");";
	
	//echo $sql."<br/>";

	$result = sql_request($sql);
	
	$answer .= "La base dsi contient ".mysqli_num_rows($result). " DE chercheurs qui n'apparaissent pas encore dans Marmotte.<br/>\n";

	while($row = mysqli_fetch_object($result))
	{
		$session = $row->LIB_SESSION.$row->ANNEE;
		$user = get_candidate_from_SIRHUS($row->NUMSIRHUS);
		if($user != null)
		{
			$sql  = "UPDATE ".reports_db;
			$sql .= " SET NUMSIRHUS=\"".$row->NUMSIRHUS."\", DKEY=\"".$row->DKEY."\" WHERE id_session=\"".$session."\"";
			$sql .= " AND section=\"".currentSection()."\" AND DKEY=\"\" AND type=\"".$row->TYPE_EVAL."\" AND nom=\"".$user->nom."\" AND prenom=\"".$user->prenom."\";";
			$res = sql_request($sql);
			global $dbh;
			$num = mysqli_affected_rows($dbh);
			if($num > 0)
			{
				$answer .= $num." evaluations chercheur ont reçu le DKEY ".$row->DKEY." with request<br/>".$sql."<br/>\n";
				continue;
			}
		}
		if($user != null)
		{
			$row->nom = $user->nom;
			$row->prenom = $user->prenom;
		}
		$answer .= "Import de l'evaluations chercheur de DKEY ".$row->DKEY."<br/>\n";
		$row->id_origine=0;
		$row->id_session = $session;
		$row->section = currentSection();
		$row->type = $row->TYPE_EVAL;
		
		addReportToDatabase($row);
	}
	return $answer;
}

function synchronizeUnitReports()
{
	$answer = "<B>Synchronisation des rapports unités</B><br/>\n";
	$sql = "SELECT * FROM ".dsidbname.".".dsi_evaluation_units_db;
	$sql.=" WHERE ( DKEY NOT IN (SELECT DKEY FROM ".marmottedbname.".".reports_db." WHERE DKEY != \"\") ";
	$sql .= " AND (";
	$sql .= "`CODE_SECTION1`=\"".currentSection()."\" OR `CODE_SECTION2`=\"".currentSection()."\"  OR `CODE_SECTION3`=\"".currentSection()."\"";
	$sql .= " OR `CODE_SECTION4`=\"".currentSection()."\" OR `CODE_SECTION5`=\"".currentSection()."\"  OR `CODE_SECTION6`=\"".currentSection()."\"";
	$sql .= " OR `CODE_SECTION7`=\"".currentSection()."\" OR `CODE_SECTION8`=\"".currentSection()."\"  OR `CODE_SECTION9`=\"".currentSection()."\"";
	$sql .= ") );";

	$res = sql_request($sql);
//	echo $sql."<br/>";

	$answer .= "La base dsi contient ".mysqli_num_rows($res). " DE unités qui n'apparaissent pas encore dans Marmotte.<br/>\n";
	while($row = mysqli_fetch_object($res))
	{
		$session = $row->LIB_SESSION.$row->ANNEE;
		$sql  = "UPDATE ".reports_db;
		$sql .= " SET DKEY=\"".$row->DKEY."\" WHERE id_session=\"".$session."\"";
		$sql .= " AND section=\"".currentSection()."\" AND DKEY=\"\" AND type=\"".$row->TYPE_EVAL."\" AND unite=\"".$row->UNITE_EVAL."\";";
		$result = sql_request($sql);

		global $dbh;
		$num = mysqli_affected_rows($dbh);
		if($num > 0)
		{
			$answer .= $num." evaluations unites ont reçu le DKEY ".$row->DKEY."<br/>\n";
			continue;
		}

		$answer .= "Import de l'evaluations unite de DKEY ".$row->DKEY."<br/>\n";
		$row->unite = $row->UNITE_EVAL;
		$row->type = $row->TYPE_EVAL;
		$row->id_session = $session;
		$row->section = currentSection();
		$row->id_origine=0;
		addReportToDatabase($row);
	}
	return $answer;
}

/* performs synchro with evaluation and returns diagnostic , empty string if nothing happaned */
function synchronize_with_evaluation()
{
	$answer = "<B>Synchronisation avec e-valuation</B><br/>\n";
	if(isSecretaire())
	{
		$answer .= synchronizeWithDsiMembers()."<br/>";
		$answer .= synchronizeSessions()."<br/>";
		$answer .= synchronizePeople()."<br/>";
		$answer .= synchronizePeopleReports()."<br/>";
		$answer .= synchronizeUnitReports()."<br/>";
	}
	return $answer;
}