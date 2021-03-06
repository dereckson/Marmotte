<?php
function cmpunits($a, $b) {
	return strnatcmp( strtolower(trim($a->nickname)), strtolower(trim($b->nickname)));
}

function unitsList($all_sections = false)
{
	$units = array();
	if($all_sections || !isset($_SESSION['all_units']))
	{
		if($all_sections || isSuperUser())
			$sql = "SELECT * FROM ".units_db." ORDER BY LOWER(nickname) ASC;";
		else
			$sql = "SELECT * FROM ".units_db." WHERE `code`!= \"\" && `section`='". real_escape_string(currentSection())."' ORDER BY LOWER(nickname) ASC;";
//			$sql = "SELECT * FROM ".units_db." WHERE `section`='". real_escape_string(currentSection())."' OR `section`=\"0\" ORDER BY nickname ASC;";
		//	$sql = "SELECT * FROM ".units_db." WHERE `section`=\"0\" ORDER BY LOWER(nickname) ASC;";

		if($result= sql_request($sql))
		  while ($row = mysqli_fetch_object($result))
		    if($row->code != "")
			$units[$row->code] = $row;

		$maxsize = 0;
		foreach($units as $unit)
			$maxsize = max($maxsize, strlen($unit->nickname));
		foreach($units as $unit)
		{
			$l = strlen($unit->nickname);
			$unit->prettyname = str_replace(" ","&nbsp;", $unit->nickname);
			$unit->prettyname .= str_pad("", $maxsize +10 - $l , " ")."- ".$unit->code;
		}

		uasort($units, 'cmpunits');
		if(!$all_sections || isSuperUser())
		  $_SESSION['all_units'] = $units;
	}
	else
	  $units = $_SESSION['all_units'];
	return $units;
}

function unitExists($code)
{
  $liste = unitsList();
  /*  foreach($liste as $key => $value)
      echo $key."<br/>";*/
  return isset($liste[$code]);
}

function unitDSIExists($code)
{
	$sql = "SELECT * FROM ".dsidbname.".".dsi_units_db." WHERE CODEUNITE=\"".$code."\";";
	$res = sql_request($sql);
	while(mysqli_fetch_object($res))
	  return true;
	return false;
}

function createUnitIfNeeded($code)
{

  if($code == "") return;

  if(!unitExists($code))
	{
try
  {
		if(unitDSIExists($code))
		{
			$sql = "SELECT * FROM ".dsidbname.".".dsi_units_db." WHERE CODEUNITE=\"".$code."\";";
			$res = sql_request($sql);
			while($row = mysqli_fetch_object($res))
			{
			  if($row->SIGLEUNI == "") $row->SIGLEUNI = $row->CODEUNITE;
				addUnit($row->SIGLEUNI,$row->CODEUNITE,$row->INTUNI,$row->NOM_DIR_UNI." ".$row->PRN_DIR_UNI);
				break;
			}
		}
		else
		{
		  addUnit($code,$code,$code,"");
		}
  }
catch(Exception $e)
  {
    echo $e->getMessage();
  }
	}
}
/*
function updateUnitData($unite, $data)
{
  if($unite == "") return;
	if(isSuperUser() && !isset($data->section))
	{
		echo "Superuser cannot update lab with generic section";
		return;
	}
	global $fieldsUnitsDB;
	if(unitExists($unite))
	{
		$sql = "";
		foreach($data as $field => $value)
			if($field != "section" && isset($fieldsUnitsDB[$field]) && $value != "")
			$sql .= " $field='$value' ";
		if($sql != "")
		{
			$sql = "UPDATE ".units_db." SET ".$sql;
			if(isSuperUser())
				$sql .=  " WHERE code='$unite' AND `section`='". real_escape_string($data->section).";";
			else
				$sql .=  " WHERE code='$unite' AND `section`='". real_escape_string($_SESSION['filter_section']).";";
			sql_request($sql);
		}
	}
	else
	{
		$sql = "INSERT INTO ".reports_db." ($sqlfields) VALUES ($sqlvalues);";
	}
}
*/

function simpleUnitsList($short = false)
{
	$units = unitsList();
	$result = array();
	foreach($units as $unit => $row)
		$result[$unit] = $short ? $row->nickname : $row->prettyname;
	return $result;
}

function addUnit($nickname, $code, $fullname, $directeur)
{
  if($code == "")
    throw new Exception("Cannot create unit with empty code");
	$sql = "SELECT * FROM ".units_db." WHERE `code`=\"".real_escape_string($code)."\";";
	$result = sql_request($sql);
	if($row = mysqli_fetch_object($result))
	{
	  if($nickname == "") $nickname = $row->nickname;
	  if($fullname == "") $fullname = $row->fullname;
	  if($directeur =="" ) $directeur = $row->directeur;
	}
	else
	{
		/* if nickname has been set we dont delete it */
	  if($nickname == "")
		$nickname = $code;
	  if($fullname == "")
	    $fullname = $nickname;
	}

	unset($_SESSION['all_units']);
	$sql = "DELETE FROM ".units_db." WHERE code = \"".$code."\" and section =\"".currentSection()."\";";
	sql_request($sql);

	$values = "\"".real_escape_string($nickname)."\",";
	$values .= "\"".str_replace(' ','',real_escape_string($code))."\",";
	$values .= "\"".real_escape_string($fullname)."\",";
	$values .= "\"".real_escape_string($directeur)."\",";
	$values .= "\"".real_escape_string(currentSection())."\"";

	$sql = "INSERT INTO ".units_db." (nickname, code, fullname, directeur, section) VALUES ($values);";
	sql_request($sql);
}

function deleteUnit($code)
{
	unset($_SESSION['all_units']);
	$sql = "DELETE FROM ".units_db." WHERE code = \"".$code."\" and section=\"".currentSection()."\";";
	sql_request($sql);
}

function delete_all_units()
{
	unset($_SESSION['all_units']);
	if(isSuperUser())
		$sql = "DELETE FROM ".units_db." WHERE 1;";
	else if(isSecretaire())
		$sql = "DELETE FROM ".units_db." WHERE section=\"".currentSection()."\";";
	sql_request($sql);
}

/*
 * Unit can be code or nickname
*/
function fromunittocode($unitdata)
{
	$units = unitsList();
	if(key_exists($unitdata, $units))
	{
		$answer = $unitdata;
		return $unitdata;
	}
	foreach($units as $unit)
	{
		if(strcasecmp($unit->nickname,$unitdata) == 0 )
		{
			$answer = $unit->code;
			return $unit->code;
		}
	}
	addUnit($unitdata, $unitdata,$unitdata,"");
	$answer = $unitdata;
	return $unitdata;
}

?>