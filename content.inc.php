
<?php 

require_once("header.inc.php");
require_once("authbar.inc.php");
require_once('display_report.inc.php');
require_once('display_reports.inc.php');
require_once('manage_filters_and_sort.inc.php');
require_once('manage_concours.inc.php');
require_once('export.inc.php');

$id = current_session_id();

if($id == "" && !isSuperUser())
{
	echo "<p>Aucune session courante n'est configurée, veuillez demander au secrétaire de créer une session via le menu Admin/Sessions<br/>";
}
if(!check_current_session_exists() && !isSuperUser())
{
  $sessions = showSessions();
  if(count($sessions) == 0)
      throw new Exception("Aucune session courante n'est configurée, veuillez demander au secrétaire de créer une session via le menu Admin/Sessions");
  else
    foreach($sessions as $sid => $data)
      {
	set_current_session_id($sid);
      }
  //	echo "<p>La session courante intitulée '".$id."' n'existe pas dans la base de données<br/>";
  //	echo "<p>Veuillez créer une session intitulée '".$id."' ou changer de session courante</p>";
}

?>

<script type="text/javascript">
   $(document).ready(function() {
       $('.sproperty').change(function() {
	   $(this).css({"color" : "#FF0000"});
	$.post( 
		  "action.php",
		  $(this).parent().serialize()
		)
	  //  	  .done(function(data) {
	      //	  alert("OK");
	  //		    })
	 .fail(function(jqXHR, textStatus, errorThrown) {
       alert( "Erreur, impossible d'enregistrer la propriété: " + errorThrown);
	   });
	 });
});

function alertSize() {
	var myWidth = 0, myHeight = 0;
	if( typeof( window.innerWidth ) == 'number' ) {
		myWidth = window.innerWidth; myHeight = window.innerHeight;
	} else if( document.documentElement && ( document.documentElement.clientWidth ||document.documentElement.clientHeight ) ) {
		myWidth = document.documentElement.clientWidth; myHeight = document.documentElement.clientHeight;
	} else if( document.body && ( document.body.clientWidth || document.body.clientHeight ) ) {
		myWidth = document.body.clientWidth; myHeight = document.body.clientHeight;
	}
	window.alert( 'Width = ' + myWidth + ' and height = ' + myHeight );
}
function getScrollXY() {
	var scrOfX = 0, scrOfY = 0;
	if( typeof( window.pageYOffset ) == 'number' ) {
		scrOfY = window.pageYOffset; scrOfX = window.pageXOffset;
	} else if( document.body && ( document.body.scrollLeft || document.body.scrollTop ) ) {
		scrOfY = document.body.scrollTop; scrOfX = document.body.scrollLeft;
	} else if( document.documentElement && ( document.documentElement.scrollLeft || document.documentElement.scrollTop ) ) {
		scrOfY = document.documentElement.scrollTop; scrOfX = document.documentElement.scrollLeft;
	}
	window.alert( 'Horizontal scrolling = ' + scrOfX + '\nVertical scrolling = ' + scrOfY );
}


function keepAlive(){
	$.ajax({
    url: 'index.php?action=ping', 
    complete: function() {
		// Rappel au bout de 5 minutes
		setTimeout(keepAlive, 30*60000);
    }
  });
}


var dirty = false;


 
$(function() {
	// Intialisation du timer pour contourner les fermetures de session
	keepAlive();
	
	// Ajout d'un style spécifique + 'dirty bit' à 'true' en cas de modifs d'un champs
	$( "#editReport" ).find(":input").change(
		function() {
			$(this).addClass("modifiedField");
			if ($(this).attr("type")!="file")
			{
				dirty = true;
			}
		}
	);
	
	// Réinitialisation du 'dirty bit' en cas de sauvegarde
	// TODO : Proposer authentification (eg via popup) si la session est fermée
	$('[name="submitandkeepediting"]').click(function(e) {
		dirty = false;
	});	
	
	// Demande de confirmation de fermeture de page en présence de données modifiées/non sauvegardées
	window.onbeforeunload = function() {
		 if(dirty) {
			 return "You have made unsaved changes. Would you still like to leave this page?";
		 }
	 }

	// Barre d'action/titre "flottante"
	var nav = $('#toolbar');
	var bd = $('#toolbar #border-bottom');
	if(nav.offset() != null)
	  {
    var navHomeY = nav.offset().top;
    var isFixed = false;
    var $w = $(window);
    $w.scroll(function() {
        var scrollTop = $w.scrollTop();
        var shouldBeFixed = scrollTop > navHomeY;
        if (shouldBeFixed && !isFixed) {
            nav.css({
                position: 'fixed',
                top: 0,
				left: nav.offset().left-5,
                width: nav.width(),
				"border-bottom-width" : '3px',
				"border-bottom-color" : '#FFFFFF',
				"border-bottom-style" : 'solid'
            });
			bd.css({
               width: nav.width(),
			   height: 15,
				"background" : "url('img/ruletrans.png')",
            });
            isFixed = true;
        }
        else if (!shouldBeFixed && isFixed)
        {
            nav.css({
                "position" : 'static',
				"border-width": 0
            });
            isFixed = false;
        }
    });
	  }
});
</script>

<?php 
function alertText($text)
{
	echo $text."\n";
	echo
	"<script>
	alert(\"".str_replace(array("\"","<br/>","<p>","</p>"),array("'","\\n","\\n","\\n"), $text)."\")
	</script>";
}
?>

<div class="large">
	<div class="content">


		<?php 
		require_once('manage_sessions.inc.php');
		require_once('manage_unites.inc.php');
		require_once('manage_rapports.inc.php');
		require_once('manage_people.inc.php');
		require_once('db.inc.php');
		require_once("upload.inc.php");



		$id_rapport = isset($_REQUEST["id"]) ? real_escape_string($_REQUEST["id"]) : -1;
		$id_origine = isset($_REQUEST["id_origine"]) ? real_escape_string($_REQUEST["id_origine"]) : 0;
		$id_toupdate = isset($_REQUEST["id_toupdate"]) ? real_escape_string($_REQUEST["id_toupdate"]) : 0;

		$action = isset($_REQUEST["action"]) ? real_escape_string($_REQUEST["action"]) : "";

		if(isset($_REQUEST["reset_filter"]))
			resetFilterValuesExceptSession();

		if(isset($_REQUEST["reset_tri"]))
			resetOrder($_REQUEST["reset_tri"]);

		function scrollToId($id)
		{
			echo('<script type="text/javascript">');
			echo('document.getElementById("'.$id.'").scrollIntoView();');
			echo('</script>');
		}
		function displayReports($centralid = 0)
		{
		  ?><script>sessionStorage.scrollPos = 0;</script><?php
			if(isSuperUser())
				return ;
			//reset_tri
			displaySummary(
					getCurrentFiltersList(), 
					getFilterValues(), 
					getSortingValues()
					);

			if($centralid != 0 && $centralid != -1)
			{
				$id  = getIDOrigine($centralid);
				scrollToId('t'.$id);
			}

		};

		function editWithRedirect($id)
		{
			?>
		<script type="text/javascript">
			window.location = "index.php?action=edit&id=<?php echo $id;?>"
			</script>
		<?php 
		}

		function viewWithRedirect($id)
		{
			?>
		<script type="text/javascript">
					window.location = "index.php?action=read&id=<?php echo $id;?>"
					</script>
		<?php 
		}


		function displayWithRedirects($id = 0)
		{
			?>
		<script type="text/javascript">	window.location = "index.php?action=view&id=<?php echo $id;?>"	</script>
		<?php
		}


		try
		{			
			/* checking permissions */
			global $actions_level;
			$level = getUserPermissionLevel();
			if(isset($actions_level[$action]) && $level < $actions_level[$action])
				throw new Exception("Vous n'avez pas le niveau de permission suffisant pour exécuter l'action '".$action."'");

			
			
			switch($action)
			{
			case 'reinitialiserconflits':
			  echo reinitializeCponflicts();
			  include 'admin/admin_concours.inc.php';
			  break;
			case 'export_to_evaluation':
			  echo export_to_evaluation();
			  include 'admin/admin_maintenance.inc.php';
			  break;
			case 'synchronizeConcours':
			  echo synchronizeConcours();
			  include 'admin/admin_maintenance.inc.php';
			  break;
			case 'synchronizeStatutsConcours':
			  echo synchronizeStatutsConcours();
			  include 'admin/admin_maintenance.inc.php';
			  break;
			case 'sync_colleges':
			  echo synchronize_colleges();
			  break;
			case 'sync_units':
			  echo synchronize_units();
			  break;
			case 'purge_units':
			  echo purge_units();
			  break;
			case 'fix_missing_data':
			  $report = "";
			  for($i = 0; $i < 55; $i++)
			      $report.=synchronizePeople($i);
			  echo $report;
			  break;
			case 'check_missing_data':
			  $report = check_missing_data();
			  if($report != "")
			    {
	  email_handler("hugo.gimbert@cnrs.fr,hugo.gimbert@labri.fr,hugooooo@gmail.com","Alerte Marmotte: données manquantes",$report,"");
			    echo $report;
			    }
			  else
			    echo "<p>Pas de données manquantes</p>";
			  break;
			case 'synchronize_sessions_with_dsi':
			  $answer = synchronizeSessions(currentSection());
					if($answer != "")
						echo $answer;
					else
						include 'admin/admin.inc.php';
					break;
				case 'synchronize_with_dsi':
				  if(isSuperUser() && isset($_REQUEST["section"]))
				    $answer = synchronize_with_evaluation($_REQUEST["section"]);
				  else
				    $answer = synchronize_with_evaluation();
				  if($answer != "")
				    echo $answer;
				  else
				    include 'admin/admin.inc.php';
				  break;
			case 'see_people':
			  include 'admin/admin_people.inc.php';
			  break;
			case 'see_units':
			  include 'admin/admin_units.php';
			  break;
			case 'see_concours':
			  include 'admin/admin_concours.inc.php';
			  break;
				case 'maintenance_on':
					set_config("maintenance", "on");
					include 'admin/admin.inc.php';
					break;
				case 'maintenance_off':
					set_config("maintenance", "off");
					include 'admin/admin.inc.php';
					break;
					/*				case 'migrate_to_eval_codes':
					migrate_to_eval_codes();
					migrate_to_avis_codes();
					break;*/
				case 'delete_units':
					delete_all_units();
					include "admin/admin_units.php";
					break;
				case 'set_people_property':
					$property = $_REQUEST["property"];
					$numsirhus = $_REQUEST["numsirhus"];
					$value = $_REQUEST["value"];
					set_people_property($property,$numsirhus, $value);
					break;
				case 'set_property':
					$property = $_REQUEST["property"];
					$id_origine = $_REQUEST["id_origine"];
					$value = $_REQUEST["value"];
					set_property($property,$id_origine, $value, isset($_REQUEST['all_reports']));
					//					displayReports($id_origine);
					break;
				case 'change_section':
					displayReports();
					break;
					/*case 'migrate':
					$types = array("users","reports","people","sessions","units");
					foreach($types as $type)
						if(isset($_REQUEST[$type]) && $_REQUEST[$type]=="on")
						migrate( $_REQUEST["section"], $_REQUEST["db_ip"], $_REQUEST["db_name"],$_REQUEST["db_user"],  $_REQUEST["db_pass"], $type);
						break;*/
				case 'addrubrique':
					add_rubrique($_REQUEST["index"], $_REQUEST["rubrique"], $_REQUEST["type"]);
					include 'admin/admin.inc.php';
					scrollToId('rubriques');
					break;
				case 'removerubrique':
					remove_rubrique($_REQUEST["index"], $_REQUEST["type"]);
					include 'admin/admin.inc.php';
					scrollToId('rubriques');
					break;
				case 'addtopic':
					add_topic($_REQUEST["index_primaire"].$_REQUEST["index_secondaire"], $_REQUEST["motcle"]);
					global $topics;
					include 'admin/admin.inc.php';
					scrollToId('config');
					break;
				case 'removetopic':
					remove_topic($_REQUEST["index"]);
					global $topics;
					include 'admin/admin.inc.php';
					scrollToId('config');
					break;
				case 'updateconfig':
					save_config_from_request();
					include 'admin/admin.inc.php';
					scrollToId('config');
					break;
				case 'delete':
					$next = next_report($id_rapport);
					$before = deleteReport($id_rapport, true);
					echo "<p>Deleted report ".$id_rapport."</p>\n";
					unset($_REQUEST['id']);
					unset($_REQUEST['id_origine']);
					//					displayWithRedirects( ($before != -1) ? $before : $next);
					if($next != -1)
						displayWithRedirects($next);
					else
						displayReports();
					break;

				case 'change_statut':
					if(isset($_REQUEST["new_statut"]))
					{
						$new_statut =  real_escape_string($_REQUEST["new_statut"]);
						change_statuts($new_statut);
						displayReports();
					}
					break;
				case 'view':
					displayReports(isset($_REQUEST["id"])?$_REQUEST["id"]:0);
					break;
				case 'deleteCurrentSelection':
					deleteCurrentSelection();
					displayReports();
					break;
				case 'affectersousjurys':
					affectersousjurys();
					include 'admin/admin.inc.php';
					break;
				case 'affectersousjurys2':
					affectersousjurys();
					displayReports();
					break;
				case 'edit':
					editReport($id_rapport);
					break;
				case 'read':
					viewReport($id_rapport);
					break;
				case 'upload':
					$create = isset($_REQUEST["create"]);
					$result= process_upload($create, null, $_FILES['uploadedfile']);
					alertText($result);
					include 'admin/admin.inc.php';
					break;
				case 'update':
					$next = next_report($id_origine);
					$rows_id = $_SESSION['rows_id'];
					$current_id = $_SESSION['current_id'];
					$previous = previous_report($id_origine);
					if(isset($_REQUEST["read"]))
						viewWithRedirect($id_origine);
					else if(isset($_REQUEST["edit"]))
						editWithRedirect($id_origine);
					else if(isset($_REQUEST["editnext"]))
						editWithRedirect($next);
					else if(isset($_REQUEST["viewnext"]))
						viewWithRedirect($next);
					else if(isset($_REQUEST["editprevious"]))
						editWithRedirect($previous);
					else if(isset($_REQUEST["viewprevious"]))
						viewWithRedirect($previous);
					else if(isset($_REQUEST["retourliste"]))
					{
						unset($_REQUEST["id_origine"]);
						unset($_REQUEST["id"]);
						displayWithRedirects($id_origine);
					}
					else if(isset($_REQUEST["deleteandeditnext"]))
					{
						$before = deleteReport($id_origine, false);
						if($before != -1)
							editWithRedirect($before);
						else if($next != -1)
							editWithRedirect($next);
						else
							displayWithRedirects();
					}
					else if(isset($_REQUEST["conflit"]))
					{
						add_conflit_to_report(getLogin(), $id_origine);
						viewWithRedirect($id_origine);
					}
					else if(isset($_REQUEST['ajoutfichiers']) && isset($_REQUEST['uploaddirfichiers']) && isset($_FILES['uploadedfilefichiers']))
					{
						$directory = $_REQUEST['uploaddirfichiers'];
						echo process_upload(true, $directory, $_FILES['uploadedfilefichiers']);
						editReport($id_origine);
					}
					else if(isset($_REQUEST['ajoutfichiers_avis']) && isset($_REQUEST['uploaddirfichiers_avis']) && isset($_FILES['uploadedfilefichiers_avis']))
					{
						$directory = $_REQUEST['uploaddirfichiers_avis'];
						echo process_upload(true, $directory,$_FILES['uploadedfilefichiers_avis']);
						editReport($id_origine);
					}
					else if(isset($_REQUEST['ajoutphoto']) && isset($_REQUEST['uploaddir_fichiers']) && isset($_FILES['uploadedfile_fichiers']))
					{
						$directory = $_REQUEST['uploaddir_fichiers'];
						echo process_upload(true,$directory,$_FILES['uploadedfile_fichiers']);
						editReport($id_origine);
					}
					else if(isset($_REQUEST['suppressionfichiers']))
					{
						if(isset($_REQUEST['deletedfichiers']))
						{
							$file = $_REQUEST['deletedfichiers'];
							if(!isSecretaire() && !is_picture($file))
								throw new Exception("You are allowed to delete images only, not documents of type '".$suffix."'");
							unlink($file);
						}
						editReport($id_origine);
					}
					else if(isset($_REQUEST['suppressionfichiers_avis']))
					{
						if(isset($_REQUEST['deletedfichiers_avis']))
						{
							$file = $_REQUEST['deletedfichiers_avis'];
							if(!isSecretaire())
								throw new Exception("Vous n etes pas autorisé à aeefacer les avis de personnalités scientifiques");
							unlink($file);
						}
						editReport($id_origine);
					}
					else
					{
					  /*					  foreach($_REQUEST as $key => $value)
					    echo $key ." - ". $value ."<br/>";
					    hh();*/
						$done = false;
						foreach($concours_ouverts as $concours => $nom)
							if(isset($_REQUEST['importconcours'.$concours]))
							{
								$done = true;
								$newreport = update_report_from_concours($id_origine,$concours, getLogin());
								editWithRedirect($newreport->id);
								break;
							}

							if(!$done)
							{
								$report = addReportFromRequest($id_origine,$_REQUEST);
								if(isset($_REQUEST["submitandeditnext"]))
									editWithRedirectReport($next);
								else if(isset($_REQUEST["submitandviewnext"]))
									viewWithRedirect($next);
								else if(isset($_REQUEST["submitandkeepediting"]))
								{
									editWithRedirect($report->id);
								}
								else if(isset($_REQUEST["submitandkeepviewing"]))
									viewWithRedirect($report->id);
								else
								{
									displayWithRedirects($report->id);
								}
									
							}
					}
					break;
				case 'change_current_session':
					if(isset($_REQUEST["current_session"]))
						$_SESSION['current_session'] = $_REQUEST["current_session"];
					displayWithRedirects();
					break;
				case 'new':
					if (isset($_REQUEST["type"]))
					{
						$type = $_REQUEST["type"];
						$nom = $_REQUEST["nom"];
						$prenom = $_REQUEST["prenom"];
						$report = newReport($type,$nom,$prenom);
						//						$report->id_origine = $id_origine;
						$nid = addReport($report);
						//
						//						displayEditableReport($report);
						echo "Rapport de type '".$type."' créé sous l'id '".$nid."'<br/>";
						include "import_export.php";
					}
					break;
				case'newpwd':
				case 'adminnewpwd':
					if (isset($_REQUEST["oldpwd"]) and isset($_REQUEST["newpwd1"]) and isset($_REQUEST["newpwd2"]) and isset($_REQUEST["login"]))
					{
						$old = real_escape_string($_REQUEST["oldpwd"]);
						$pwd1 = real_escape_string($_REQUEST["newpwd1"]);
						$pwd2 = real_escape_string($_REQUEST["newpwd2"]);
						$login = real_escape_string($_REQUEST["login"]);
						$envoiparemail = isset($_REQUEST["envoiparemail"])  ? real_escape_string($_REQUEST["envoiparemail"]) : false;

						if (($pwd1==$pwd2))
						{
							if (changePwd($login,$old,$pwd1,$pwd2,$envoiparemail))
								echo "<p><strong>Mot de passe modifié avec succès.</strong></p>";
						}
						else
							throw new Exception("Erreur :</strong> Les deux saisies du nouveau mot de passe  diffèrent, veuillez réessayer.</p>");
					}
					include 'admin/admin.inc.php';
					scrollToId("membres");
					break;
				case 'admin':
					include "admin/admin.inc.php";
					break;
				case 'admindeleteaccount':
					if (isset($_REQUEST["login"]))
					{
						$login = $_REQUEST["login"];
						deleteUser($login);
						include "admin/admin.inc.php";
						scrollToId("membres");
					}
					break;
				case 'mergeUsers':
					mergeUsers($_REQUEST["old_login"], $_REQUEST["new_login"]);
					include "admin/admin.inc.php";
					scrollToId("importaccounts");
					break;
				case 'admindeleteallaccounts':
					deleteAllUsers();
					include "admin/admin.inc.php";
					scrollToId("membres");
					break;
				case 'importaccountsfromJanus':
				  $result = synchronizeWithDsiMembers(currentSection());
					if($result != "")
						echo $result;
					else
						include "admin/admin.inc.php";
					break;
				case 'infosrapporteur':
					if (isset($_REQUEST["login"]))
					{
						global  $concours_ouverts;
						$login = $_REQUEST["login"];
						$permissions = isset($_REQUEST["permissions"]) ? $_REQUEST["permissions"] : "";
						$college = isset($_REQUEST["college"]) ? $_REQUEST["college"] : "";
						$sections = isset($_REQUEST["sections"]) ? $_REQUEST["sections"] : "";
						$section_code = isset($_REQUEST["section_code"]) ? $_REQUEST["section_code"] : "";
						$CID_code = isset($_REQUEST["CID_code"]) ? $_REQUEST["CID_code"] : "";
						$section_role = isset($_REQUEST["section_role"]) ? $_REQUEST["section_role"] : "";
						$CID_role = isset($_REQUEST["CID_role"]) ? $_REQUEST["CID_role"] : "";
						foreach($concours_ouverts as $concours => $nom)
							if(isset($_REQUEST["sousjury".$concours]))
							addSousJury($concours, $_REQUEST["sousjury".$concours], $login);
						if(isSuperUser())
						  changeUserInfos($login,$permissions,$sections,$section_code, $section_role, $CID_code, $CID_role,$college);
						include "admin/admin.inc.php";
						scrollToId('infosrapporteur');
					}
					break;
				case 'checkpwd':
					if(isset($_REQUEST["password"]))
					{
						$password = $_REQUEST["password"];
						checkPasswords($password);
					}
					include "admin/admin.inc.php";
					scrollToId("membres");
					break;
				case 'adminnewaccount':
					if (isset($_REQUEST["email"]) and isset($_REQUEST["description"]) and isset($_REQUEST["newpwd1"]) and isset($_REQUEST["newpwd2"]))
					{
						$desc = $_REQUEST["description"];
						$pwd1 = $_REQUEST["newpwd1"];
						$pwd2 = $_REQUEST["newpwd2"];
						$login = $_REQUEST["email"];
						$email = $_REQUEST["email"];
						$permissions = $_REQUEST["permissions"];
						$envoiparemail = isset($_REQUEST["envoiparemail"]) && ($_REQUEST["envoiparemail"] === 'on');
						if (($pwd1!=$pwd2))
							throw new Exception("Les deux saisies du nouveau mot de passe diffèrent, veuillez réessayer");
						echo "<p><strong>".createUser(
								$login,
								$pwd2,
								$desc,
								$email,
								"","0",
								"","",
								"","",
								$envoiparemail)."</p></strong>";
					}
					include "admin/admin.inc.php";
					scrollToId("membres");
					break;
			case 'delete_prerapports':
					if (isset($_REQUEST["sessionid"]))
					{
					  deletePreRapports(real_escape_string($_REQUEST["sessionid"]));
					  include "admin/admin.inc.php";
					}
			  break;
			       case 'admindeleteprerapports':
					if (isset($_REQUEST["sessionid"]))
					{
					  deletePreRapports(real_escape_string($_REQUEST["sessionid"]));
					  include "admin/admin.inc.php";
					  scrollToId("sessions");
					}
				 break;
			case 'delete_concours':
				case 'admindeletesession':
					if (isset($_REQUEST["sessionid"]))
					{
						deleteSession(real_escape_string($_REQUEST["sessionid"]), isset($_REQUEST["supprimerdossiers"]));
						if(!isSuperUser())
							displayWithRedirects();
					}
					break;
				case 'changepwd':
					include "changePwd.inc.php";
					break;
				case 'add_concours':
					$concours = (object) array();
					$fields = array("code", "intitule",
							"sousjury1","sousjury2", "sousjury3", "sousjury4",
							"president1", "president2", "president3", "president4"
					);
					foreach($fields as $field)
						$concours->$field = isset($_REQUEST[$field]) ? $_REQUEST[$field] : "";
					setConcours($concours);
					include "admin/admin.inc.php";
					scrollToId('concours');
					break;
				case 'delete_concours':
					deleteConcours($_REQUEST["code"]);
					include "admin/admin.inc.php";
					scrollToId('concours');
					break;
				case "statutconcours":
					$code = isset($_REQUEST["code"]) ? $_REQUEST["code"] : "";
					$statut = isset($_REQUEST["statut"]) ? $_REQUEST["statut"] : "";
					setConcoursStatut($code, $statut);
					include "admin/admin.inc.php";
					scrollToId('concours');
					break;
				case 'ajoutlabo':
					if(isset($_REQUEST["nickname"]) and isset($_REQUEST["code"]) and isset($_REQUEST["fullname"]) and isset($_REQUEST["directeur"]))
					{
						addUnit(
								$_REQUEST["nickname"],
								$_REQUEST["code"],
								$_REQUEST["fullname"],
								$_REQUEST["directeur"]
						);
						echo "Unité \"".$_REQUEST["code"]."\" ajoutée à la liste des unités de la section (dans Marmotte).<br/>";
					}
					include "admin/admin.inc.php";
					//					scrollToId('ajout');
					break;
				case 'deletelabo':
					if(isset($_REQUEST["unite"]))
					{
						deleteUnit(real_escape_string($_REQUEST["unite"]));
						echo "Deleted unit \"".real_escape_string($_REQUEST["unite"])."\"<br/>";
					}
					include "admin/admin.inc.php";
					scrollToId('ajout');
					break;
				case 'mailing':
				case 'email_rapporteurs':
					include 'mailing.inc.php';
					break;
				case 'trouverfichierscandidats':
					link_files_to_candidates();
					include "admin/admin.inc.php";
					break;
				case 'creercandidats':
					creercandidats();
					include "admin/admin.inc.php";
					break;
				case 'injectercandidats':
					injectercandidats();
					include "admin/admin.inc.php";
					break;
				case "displayimportexport":
					include "import_export.php";
					break;
				case "";
				default:
					if(substr($action,0,3)=="set")
					{
						$fieldId = substr($action,3);
						$newvalue = isset($_REQUEST['new'.$fieldId]) ? real_escape_string($_REQUEST['new'.$fieldId]) : "";
						$newid = change_report_property($id_toupdate, $fieldId, $newvalue);
						displayWithRedirects($newid);
					}
					else
					{
						if(isSuperUser())
						{
							include "admin/admin.inc.php";
						}
						else
						{
							echo get_config("welcome_message");
							displayWithRedirects();
						}
					}
					break;
			}
		}
		catch(Exception $exc)
		{
			$text = 'Erreur: '.$exc->getMessage();
			alertText($text);
		}
		?>
	</div>
</div>
<br/>
<br/>
<br/>
<br/>