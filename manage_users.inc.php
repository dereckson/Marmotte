<?php

require_once('config.inc.php');
require_once('manage_sessions.inc.php');
require_once('generate_xml.inc.php');
require_once('authenticate_tools.inc.php');

function createhtpasswd()
{
	$list = listUsers(true);
	if($handle=fopen(".htpasswd","w"))
	{
		foreach($list as $user => $data)
			fwrite($handle,$user.":".$data->passHash."\n");
		fclose($handle);
		echo "Generated htpasswd.<br/>";
	}
	else
	{
		throw new Exception("Failed to open htpasswd file for writing");
	}

}

function belongsToSection($login, $section)
{
	$all_sections = getSections($login);
	return in_array($section, $all_sections);
};

function currentSection()
{
	return $_SESSION['filter_section'];	
}

function change_current_section($section)
{
	if(!belongsToSection(getLogin(), $section))
		throw new Exception("Cannot change current section, user ".$login." does not belong to section ".$section);

	$sql = "UPDATE ".users_db." SET last_section_selected='";
	$sql .= real_escape_string($section);
	$sql .= "'WHERE login='".real_escape_string(getLogin())."';";
	sql_request($sql);
	$_SESSION['filter_section'] = $section;
	unset($_SESSION["config"]);
	$_SESSION['filter_id_session'] = get_config("current_session");
}

/* Caching users list for performance */

function listRapporteurs()
{
	global $users_not_rapporteur;

	$empty[''] = (object) array();
	$empty['']->description = "";
	$result = array_merge($empty,listUsers());

	foreach($users_not_rapporteur as $user)
		unset($result[$user]);

	return $result;
}

function listNomRapporteurs()
{
	global $users_not_rapporteur;

	$result = array();
	$result[''] = "";
	$users = listUsers();

	foreach($users as $login => $data)
		if(!in_array($login, $users_not_rapporteur))
		$result[$login] = $data->description;

	return $result;
}

function listUsers($forcenew = false)
{
	if($forcenew)
		unset($_SESSION['all_users']);

	if(!isset($_SESSION['all_users']))
	{
		$listusers = array();
		//$sql = "SELECT * FROM ".users_db." WHERE `section`='". real_escape_string($_SESSION['filter_section'])."' ORDER BY description ASC;";
		$sql = "SELECT * FROM ".users_db." ORDER BY description ASC;";
		$result= sql_request($sql);
		if($result ==  false)
			throw new Exception("Failed to process sql query ".$sql.": ".mysql_error());
		$section = currentSection();
		while ($row = mysqli_fetch_object($result))
		{
			$sections = explode(";", $row->sections);
			if(isSuperUser() or in_array($section,$sections) )
				$listusers[$row->login] = $row;
		}
		$_SESSION['all_users'] = $listusers;
	}
	$all_users = $_SESSION['all_users'];
	return $all_users;
}

function simpleListUsers()
{
	$users = listUsers();
	$result = array();
	foreach($users as $user => $row)
		$result[$row->login] = $row->description;
	return $result;
}

function getUserPermissionLevel($login = "")
{	
	if ($login=="" || $login == getLogin())
		return isset($_SESSION['permission']) ? $_SESSION['permission'] : 0;

		if(!isset($_SESSION["login"]))
			throw new Exception("User not logged in !");
		$login = $_SESSION["login"];
	
	$login = strtolower($login);
	if ($login == "admin")
		return NIVEAU_PERMISSION_SUPER_UTILISATEUR;
	$users = listUsers();
	if (isset($users[$login]))
	{
		$data = $users[$login];
		return $data->permissions;
	}
	else
	{
		removeCredentials();
		throw new Exception("Unknown user '" + $login + "'");
	}
}

function genere_motdepasse($len=10)
{
	/*return openssl_random_pseudo_bytes($len);*/
	date_default_timezone_set("Europe/Paris");
	return substr(crypt(date("%l %u")),3,13);
}

function isSuperUser($login = "")
{
	if($login == "")
		$login = getLogin();
	return getUserPermissionLevel($login) >= NIVEAU_PERMISSION_SUPER_UTILISATEUR;
};

function isSecretaire($login = "")
{
	if($login == "")
		$login = getLogin();
	return getUserPermissionLevel($login) >= NIVEAU_PERMISSION_SECRETAIRE;
};

function getLogin()
{
	if (isset($_SESSION["login"]))
		return strtolower($_SESSION["login"]);
	else
		return "";
}

function getSecretaire()
{
	$users = listUsers();
	foreach($users as $user)
		if($user->permissions == NIVEAU_PERMISSION_SECRETAIRE)
		return $user;
	return null;
}

function getPresident()
{
	$users = listUsers();
	foreach($users as $user)
		if($user->permissions == NIVEAU_PERMISSION_PRESIDENT)
		return $user;
	return null;
}

function isBureauUser($login = "")
{
	return getUserPermissionLevel($login) >= NIVEAU_PERMISSION_BUREAU;
};

function isRapporteurUser($login = "")
{
	return getUserPermissionLevel($login) >= NIVEAU_PERMISSION_BASE;
};

function isSousJury($sousjury, $login = "")
{
	if($login == "" )
		$login = getLogin();
	$users = listUsers();
	if($sousjury != "" && $users[$login]->sousjury != "")
	{
		$test = strpos($users[$login]->sousjury, $sousjury);
		return ($test === 0 || $test != false);
	}
	else if($sousjury == "" && $users[$login]->sousjury == "")
		return true;
	else
		return false;
}

function isPresidentSousJury($sousjury = "")
{
	global $presidents_sousjurys;
	if($sousjury != "")
		return (isset($presidents_sousjurys[$sousjury]) && getLogin() == $presidents_sousjurys[$sousjury]);
	else
	{
		foreach($presidents_sousjurys as $pres => $login)
			if($login == getLogin())
			return true;
	}
	return false;
}

function changePwd($login,$old,$new1,$new2, $envoiparemail)
{
	$currLogin = getLogin();
	$users = listUsers();
	if (authenticateBase($login,$old) or isSecretaire())
	{
		$oldPassHash = getPassHash($login);
		if ($oldPassHash != NULL)
		{
			$newPassHash = crypt($new1, $oldPassHash);
			$sql = "UPDATE ".users_db." SET passHash='$newPassHash' WHERE login='".real_escape_string($login)."';";
			sql_request($sql);

			try
			{
				createhtpasswd();
			}
			catch(Exception $e)
			{
				echo $e->getMessage();
			}

			if(getLogin() == $login)
				addCredentials($login,$new1);

			if($envoiparemail)
			{
				$body = "Votre mot de passe pour le site \r\n".curPageURL()."\r\n a été mis à jour:\r\n";
				$body .= "\t\t\t login: '".$login."'\r\n";
				$body .= "\t\t\t motdepasse: '".$new1."'\r\n";
				$body .= "\r\n\r\n\t Amicalement, ".get_config("secretaire").".";
				$cc = "";
				foreach($users as $user)
				{
					if($user->login == $currLogin && $currLogin != $login)
					{
						$cc = $user->email;
						break;
					}
				}
				email_handler($users[$login]->email,"Votre compte Marmotte",$body,$cc);
			}

			return true;
		}
	}
	else
		throw new Exception("La saisie du mot de passe courant est incorrecte, veuillez réessayer.");
}

function changeUserInfos($login,$permissions, $sections)
{
	if($permissions >= NIVEAU_PERMISSION_SUPER_UTILISATEUR)
		$sections = "0";
	if(isSuperUser())
		$sql = "UPDATE ".users_db." SET sections=$sections permissions=$permissions WHERE login='".real_escape_string($login)."';";
	if (isSecretaire())
		$sql = "UPDATE ".users_db." SET permissions=$permissions WHERE login='".real_escape_string($login)."';";
	
	sql_request($sql);
	
	unset($_SESSION['all_users']);

	
}

function existsUser($login)
{
	$users = listUsers();
	return array_key_exists($login, $users);
}

function addUserToSection($login,$section)
{
	if (isSecretaire())
		$sql = "UPDATE ".users_db." SET sections=$section;`sections` WHERE login='".real_escape_string($login)."';";
}

function createUser($login,$pwd,$desc,$email, $sections, $permissions, $envoiparemail = false)
{
	$login = strtolower($login);

	if($login == "admin")
		$sections = "0";
		
	if (isSecretaire())
	{
		if(existsUser($login))
			throw new Exception("Failed to create user: le login '".$login."' est déja utilisé.");
		if($desc == "")
			throw new Exception("Failed to create user: empty description.");

		if(!isSuperUser())
			$sections = currentSection();
		
		unset($_SESSION['all_users']);

		$passHash = crypt($pwd);
		$sql = "INSERT INTO ".users_db." (login,sections,permissions,passHash,description,email,tel) VALUES ('";
		$sql .= real_escape_string($login)."','";
		$sql .= real_escape_string($sections)."','";
		$sql .= real_escape_string($permissions)."','";
		$sql .= real_escape_string($passHash)."','";
		$sql .= real_escape_string($desc)."','";
		$sql .= real_escape_string($email)."','');";

		$result = sql_request($sql);
		
		createhtpasswd();

		if($envoiparemail)
		{
			$body = "Marmotte est un site web destiné à faciliter la répartition, le dépôt, l'édition et la production\r\n";
			$body .= "des rapports par les sections du comité national.\r\n";
			$body .= "\r\nLe site est accessible à l'adresse \r\n\t\t\t".curPageURL()."\r\n";
			$body .= "\r\nCe site a été développé par Hugo Gimbert et Yann Ponty.\r\n";
			$body .= "\r\nL'accès au site est restreint aux membres de la section ".get_config("section_nb")." qui doivent s'authentifier pour y accéder et déposer, éditer ou consulter des rapports.\r\n";
			$body .= "\r\nUn compte Marmotte vient d'être créé pour vous:\r\n\r\n";
			$body .= "\t\t\t login: '".$login."'\r\n";
			$body .= "\t\t\t motdepasse: '".$pwd."'\r\n";
			$body .= "\r\nLors de votre première connexion vous pourrez changer votre mot de passe.\r\n";
			$body .= "\r\n\r\n\t Amicalement, ".get_config("secretaire").".";

			$cc = "";
			$currLogin = getLogin();
			$users = listUsers();
			foreach($users as $user)
			{
				if($user->login == $currLogin && $currLogin != $login)
				{
					$cc = $user->email;
					break;
				}
			}
			email_handler($email,"Votre compte Marmotte",$body,$cc);
		}
		
		return "Utilisateur ".$login." créé avec succès.";
	}
}

function deleteUser($login)
{
	/* Since a user can be shared by several sections,
	 * only superuser can delete a user
	 */
	if (isSuperUser())
	{
		unset($_SESSION['all_users']);
		$sql = "DELETE FROM ".users_db." WHERE login='".real_escape_string($login)."';";
		sql_request($sql);
		createhtpasswd();
	}
}


function affecte_sous_jurys($login, $sousjurys)
{
	$sql = "SELECT * FROM ".concours_db." WHERE section='".currentSection()."' and session='".current_session_id()."';";
	sql_request($sql);
	
	foreach($sousjurys as $concours => $sousjurys)
	{
		
	}
}

?>