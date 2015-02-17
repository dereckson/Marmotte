<?php

error_reporting(E_ALL);
ini_set('display_errors', TRUE);
ini_set('display_startup_errors', TRUE);
ini_set('xdebug.collect_vars', 'on');
ini_set('xdebug.collect_params', '4');
ini_set('xdebug.dump_globals', 'on');
ini_set('xdebug.dump.SERVER', 'REQUEST_URI');
ini_set('xdebug.show_local_vars', 'on');

ini_set("session.gc_maxlifetime", 3600);
session_start();

if(!isset($_SESSION["login"]))
	$_SESSION["login"] = "";

require_once("db.inc.php");
require_once('authenticate_tools.inc.php');
//invalide
try
{
	try
	{		
		db_connect($servername,$dbname,$serverlogin,$serverpassword);		
	}
	catch(Exception $e)
	{
		include("header.inc.php");
		echo "<h1>Failed to connect to database: ".$e."</h1>";
		db_from_scratch();
	}
	
	global $dbh;
	if($dbh)
	{
		if(!isset($_SESSION['checked_admin_password']))
		{
			createAdminPasswordIfNeeded();
			$_SESSION['checked_admin_password'] = true;
		}
		/*
		if(authenticateBase('admin','password'))
			echo "The 'admin' password is 'password', please change it right after login.";
			*/
		
		$action = isset($_REQUEST["action"]) ? mysqli_real_escape_string($dbh, $_REQUEST["action"]) : "";
		$errorLogin = 0;
		if($action == "authjanus")
		{
			echo "Authentification JANUS '".$_SERVER["REMOTE_USER"]."'<br/>";
			if($_SERVER["REMOTE_USER"] == "")
				removeCredentials();
		}
		if($action == "auth")
		{
			removeCredentials();
			
			if(isset($_REQUEST["login"]) and isset($_REQUEST["password"]) and isset($_REQUEST["type_authentification"]))
			{
				$login =  $_REQUEST["login"];
				$pwd =  $_REQUEST["password"];
				$type = $_REQUEST["type_authentification"];
				
				addCredentials($login,$pwd);
				
				if($type == "janus")
				{
					require 'PMSP/Pmsp.php';
					
					
					$pubkey = "/etc/pmsp/pmsp.pub";
					$server = "https://vigny.dr15.cnrs.fr/secure/pmsp-server.php";
					$appid = "PMSP Marmotte";
					$attributes = 'mail,ou,cn,sn,givenName,displayname';
					
					//if (/* l'utilisateur n'est pas encore authentifié */) {
					$pmsp = new Pmsp($server, $pubkey, $appid, "http://127.0.0.1/index.php?action=authjanus");
					
					$pmsp->authentify($attributes);
										
					/*
					 * A cet endroit $_SERVER[$attr] contient les valeurs de tous les attributs
					* indiqués dans la liste $attributes, sauf ceux que le fournisseur de service
					* qui héberge le serveur PMSP n'a pas obtenu via Shibboleth.
					* L'attribut REMOTE_USER est automatiquement ajouté à la liste.
					* Pour Janus, c'est l'adresse de messagerie en minuscules
					*/
					$login = $_SERVER['REMOTE_USER'];
					$pwd = "";
					$username = $_SERVER['cn'];
					$userlaboratory = $_SERVER['ou'];
					
				//filter_id_sess	
				}
				if (!authenticate())
				{
					$errorLogin = 1;
				}
			}
		}
		
		if(!authenticate() || $action == 'logout' || ($errorLogin == 1))
		{
			removeCredentials();
			include("header.inc.php");
			include("authenticate.inc.php");
		}
		else
		{	
			if(!isset($_SESSION['filter_id_session']))
			{
				require_once("config_tools.inc.php");
				$_SESSION['filter_id_session'] = get_config("current_session");
			}
			
			require_once("utils.inc.php");
			require_once("manage_users.inc.php");
			if(isSecretaire() && !isset($_SESSION["htpasswd"]))
			{
				createhtpasswd();
				$_SESSION["htpasswd"] = "done";
			}
				
			switch($action)
			{
				case 'adminnewsession':
					if (isset($_REQUEST["sessionname"]) and isset($_REQUEST["sessionannee"]))
					{						
						$name = real_escape_string($_REQUEST["sessionname"]);
						$annee = real_escape_string($_REQUEST["sessionannee"]);
						require_once('manage_sessions.inc.php');
						createSession($name,$annee);
						$_REQUEST["action"] = 'admin';
					}
					else
						echo "<p><strong>Erreur :</strong> Vous n'avez fourni toutes les informations nécessaires pour créer une session, veuillez nous contacter (Yann ou Hugo) en cas de difficultés.</p>";
					break;
				case 'sessioncourante':
					if(isset($_REQUEST["sessionname"]))
					{
						require_once('config_tools.inc.php');
						$id = real_escape_string($_REQUEST["sessionname"]);
						set_config('current_session',$id);
						set_current_session_id($id);
						$_REQUEST["action"] = 'admin';
					}
					break;
				case 'change_role':
					$role = isset($_REQUEST["role"]) ? $_REQUEST["role"] : 0;
					$role = min( $role, getUserPermissionLevel("",false));
					$_SESSION["permission_mask"] = $role;
				break;
					
			}

		try{
			/* should not be here but ... */
			if(isset($_REQUEST['filter_section']))
				change_current_section($_REQUEST['filter_section']);
			
			$id = current_session_id();
			
			if($id == "" && !isSuperUser())
			{
				echo "<p>Aucune session courante n'est configurée, veuillez créer une session via le menu Admin/Sessions<br/>";
			}
			else
			{
				if(!check_current_session_exists() && !isSuperUser() && isSecretaire())
				{
					echo "<p>La session courante intitulée '".$id."' n'existe pas dans la base de données<br/>";
					echo "<p>Veuillez créer une session intitulée '".$id."' ou changer de session courante</p>";
				}
			}
					include("content.inc.php");
			}
			catch(Exception $exc)
			{
				echo '<p>Erreur: '.$exc.'</p>';
			}
		}
	db_disconnect();
	}
}
catch(Exception $e)
{
	include("header.inc.php");
	echo $e->getMessage();
}
?>
</body>
</html>
