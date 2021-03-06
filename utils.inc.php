<?php
require_once('config.inc.php');
require_once('db.inc.php');
require_once('manage_users.inc.php');
require_once('manage_unites.inc.php');

//set_exception_handler('exception_handler');
//set_error_handler('error_handler');
function getTypesEval($id_session,$section)
{
	$finalResult = array();
	$sql = "SELECT DISTINCT type FROM (SELECT tt.*, ss.nom AS nom_session, ss.date AS date_session FROM ";
	$sql .= reports_db." tt INNER JOIN ( SELECT id, MAX(date) AS date FROM ".reports_db;
	$sql .= " GROUP BY id_origine) mostrecent ON tt.date = mostrecent.date, ".sessions_db;
	$sql .=" ss WHERE ss.id=tt.id_session) difftypes WHERE id_session=$id_session AND section=$section ORDER BY type DESC;";
	
	$result=mysql_query($sql);
	while ($row = mysql_fetch_object($result))
	{
		if ($row->type)
			$finalResult[] = $row->type;
	}
	return $finalResult;
}


function highlightDiff(&$prevVals,$key,$val)
{
	if (isset($prevVals[$key]))
	{
		if ($prevVals[$key]==$val)
		{
			$prevVals[$key] = $val;
			return "<span class=\"faded\">$val</span>";
		}
		else
		{
			$prevVals[$key] = $val;
			return "<span class=\"highlight\">$val</span>";
		}
	}
	$prevVals[$key] = $val;
	return $val;
}



function fieldDiffers($prevVals,$key,$val)
{
	if(isset($prevVals[$key]))
	{
		if ($prevVals[$key]==$val)
		{
			return false;
		}
		else {
			return true;
		}
	} return true;
}


function remove_br($str)
{
	return str_replace("<br />","",$str);
}
function insert_br($str)
{
	return str_replace("\n","<br />",$str);
}


function array_remove_by_value($array, $value)
{
	return array_values(array_diff($array, array($value)));
}

function is_picture($file)
{
	if(strlen($file) < 4) return false;
	$suffix = strtolower(substr($file,-3,3));
	return $suffix == "png" || $suffix == "jpg" || $suffix == "bmp";
}

function message_handler($subject,$body)
{
	$headers = 'From: '.get_config("webmaster"). "\r\n" . 'Reply-To: '.get_config("webmaster"). "\r\n" .'X-Mailer: PHP/' . phpversion()."\r\n";
	mail(get_config("webmaster"), $subject, "\r\n".$body."\r\n", $headers);
}

function email_handler($recipient,$subject,$body, $cc = "",$from="")
{
  if($from == "") $from = get_config("webmaster");
	echo "Envoi d'email a '".$recipient."' avec sujet '".$subject."'... ";
	
	$headers = 'From: '.$from. "\r\n";
	if($cc != "")
		$headers.= 'CC: ' .$cc . "\r\n";
	$headers .= 'Reply-To: '.$from. "\r\n".'Content-Type: text/plain; charset="UTF-8"\r\n'.'X-Mailer: PHP/' . phpversion()."\r\n";

	$result = mail($recipient, $subject, "\r\n".$body."\r\n", $headers);

	if($result == false)
	{
		echo "failed!<br/>\n";
		throw new Exception("Could not send email to ".$recipient." with subject ".$subject);
	}
		echo "ok<br/>\n.";
}


function replace_accents($string)
{
	return str_replace( array('à','á','â','ã','ä', 'ç', 'è','é','ê','ë', 'ì','í','î','ï', 'ñ', 'ò','ó','ô','õ','ö', 'ù','ú','û','ü', 'ý','ÿ', 'À','Á','Â','Ã','Ä', 'Ç', 'È','É','Ê','Ë', 'Ì','Í','Î','Ï', 'Ñ', 'Ò','Ó','Ô','Õ','Ö', 'Ù','Ú','Û','Ü', 'Ý'), array('a','a','a','a','a', 'c', 'e','e','e','e', 'i','i','i','i', 'n', 'o','o','o','o','o', 'u','u','u','u', 'y','y', 'A','A','A','A','A', 'C', 'E','E','E','E', 'I','I','I','I', 'N', 'O','O','O','O','O', 'U','U','U','U', 'Y'), $string);
}

function normalizeName($name)
{
	return str_replace('\' ', '\'', ucwords(strtolower($name)));
}


/*
function stripAccents($string){
	return strtr($string,"'àáâãäçèéêëìíîïñòóôõöùúûüýÿÀÁÂÃÄÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ",
			' aaaaaceeeeiiiinooooouuuuyyAAAAACEEEEIIIINOOOOOUUUUY');
			}*/


function exception_handler($exception)
{
	echo "<h1>".$exception->getMessage()."</h1>";
	//message_handler("Marmotte webpage :exception ",$exception->getMessage());
}


function error_handler($errno, $errstr, $errfile, $errline)
{
	$body= "Number:".$errno."\r\n String:".$errstr."\r\n File:".$errfile."\r\n Line:".$errline;
	echo "<h1>".$body."</h1>";
	//message_handler("Marmotte webpage :error ",$body);
}

function curPageURL() {
	$pageURL = 'http';
	if (isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] == "on") {
$pageURL .= "s";
}
$pageURL .= "://";
if (isset($_SERVER["SERVER_PORT"]) && $_SERVER["SERVER_PORT"] != "80") {
		$pageURL .= $_SERVER["SERVER_NAME"].":".$_SERVER["SERVER_PORT"].$_SERVER["REQUEST_URI"];
	} else {
		$pageURL .= (isset($_SERVER["SERVER_NAME"]) ? $_SERVER["SERVER_NAME"] : "").(isset($_SERVER["REQUEST_URI"]) ? $_SERVER["REQUEST_URI"] : "");
	}
	return $pageURL;
}


function my_iconv($text)
{
  ini_set('mbstring.substitute_character', "none");
  $text= mb_convert_encoding($text, "UTF-8", "UTF-8"); 
  return iconv("UTF-8","ASCII//TRANSLIT",$text);
}
//Returns the name of the file
function filename_from_doc($doc)
{
  global $id_rapport_to_label;
  $nom = str_replace( array("'"," ","/"), array("","_"," ") , mb_convert_case(replace_accents($doc->nom), MB_CASE_TITLE));
	$prenom = mb_convert_case(replace_accents($doc->prenom), MB_CASE_TITLE);
	$type = $doc->type;
	//substr($id_rapport_to_label[$doc->type], 0, 10);
	$nom = my_iconv($nom);
	$prenom = my_iconv($prenom);

	$sessions = sessionArrays();
	$session = isset($sessions[$doc->id_session]) ? $sessions[$doc->id_session] : "";
	return filename_from_params($nom, $prenom, $doc->grade_rapport, $doc->unite, $type, $session, $doc->avis, $doc->concours, $doc->sousjury, $doc->intitule);
}

function filename_from_params($nom, $prenom, $grade, $unite, $type, $session, $avis, $concours = "", $sousjury="", $intitule = "")
{
  global $typesRapportsAll;
  global $tous_avis;

  if(isset($tous_avis[$avis]))
     $avis = $tous_avis[$avis];

  $pretty_type = ($intitule == "") ? ( isset($typesRapportsAll[$type]) ? $typesRapportsAll[$type] : $type) : $intitule;
  $pretty_type = str_replace("Candidature pour une promotion","Promo",$pretty_type);
  if(strlen($pretty_type) >= 20)
    {
      $offs = strpos($pretty_type," ",20);
      if($offs !== false)
	$pretty_type = substr($pretty_type,0,$offs);
    }
 
	$liste_unite = unitsList();

	
	$section = "S".currentSection();

	if(strlen($session) >5)
	  $session = substr($session,0,1).substr($session,strlen($session)-2);

	if(isset($liste_unite[$unite]))
		$unite = $unite . " - " . $liste_unite[$unite]->nickname;

	if(is_unite_type($type))
	{

		if(is_ecole_type($type))
			$result = $session." - ".$section." - ".$pretty_type." - ".$avis." - ".$intitule." - ".$nom." - ".$unite;
		else
			$result =  $session." - ".$section." - ".$pretty_type." - ".$avis." - ".$unite;
	}
	else if( is_concours_type($type) || $type == "Audition" || $type == "Classement")
	{
	  if(is_classement($type))
	    $result =  $session." - ".$concours." - ".$pretty_type." - ".$avis." - ".$nom." ".$prenom;
	else
		$result  =  $session." - ".$concours." - ".$pretty_type." - ".$grade." - ".$avis." - ".$nom." ".$prenom;
	}
	else
		$result =  $session." - ".$section." - ".$pretty_type." - ".$grade." - ".$avis." - ".$unite." - ".$nom." ".$prenom;
	$result = str_replace(array("'","(",")","/"),array(" ","","","-"),$result);
	return replace_accents($result);
}


function getStyle($fieldId,$odd, $conflict = false)
{
	global $fieldsIndividualAll;
	global $fieldsCandidat;
	$individual = isset($fieldsIndividualAll[$fieldId]) or isset($fieldsCandidat[$fieldId]);
	
	$rapp2 = ((substr($fieldId, -1)==="2")and !($individual));
	if ($odd)
	{
		$style =  "oddrow";
	}			
	else
	{
		$style =  "evenrow";
	}
	
	if ($rapp2)
	{  $style .= "Bis"; }
	else if ($individual)
	{  $style .= "Individual"; }

	if ($conflict)
	{
		$style .=  "Conflict";
	}			
	
	return $style;
}
?>