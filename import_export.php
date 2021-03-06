<?php 
require_once('config_tools.inc.php');
require_once('generate_csv.inc.php');
require_once('manage_unites.inc.php');
require_once('manage_sessions.inc.php');


function displayImport()
{
	global $typeImports;

	?>
<form enctype="multipart/form-data" action="index.php" method="post">
	<table>

		<tr>
			<td><input type="hidden" name="type" value="evaluations"></input> <input
				type="hidden" name="action" value="upload" /> <input type="hidden"
				name="MAX_FILE_SIZE" value="10000000" />
			</td>
		</tr>
		<tr>
			<td><input name="uploadedfile" type="file" /> <br /> <input
				type="submit" value="Mettre à jour le ou les rapports" />
			</td>
		</tr>
	</table>
</form>

<?php 

}

function displaySecretaryImport()
{
  if(isSecretaire() && !is_current_session_concours())
	{
		?>

	  <h2>Ajout d&apos;un rapport</h2>
<form enctype="multipart/form-data" action="index.php" method="post">
	<table>
		<tr>			<td><input type="hidden" name="id_origine" value="0" /> <input
				type="hidden" name="action" value="new" />
			</td>
		</tr>
		<tr>
			<td>Choix du type de rapport</td>
			<td><select name="type" type="hidden">
					<?php
	    global $typesRapportsAll;
					$types = $typesRapportsAll;

					if(isset($_REQUEST["type"]))
					  $ttype = $_REQUEST["type"];
					else
					  $ttype = "";
					global $typesRapportsConcours;
					foreach($types as $type => $name)
					  {
					    if(isset($typesRapportsConcours[$type])) continue;
					  if($type != $ttype)
					    echo '<option value='.$type.'>'.$name.'</option><br/>'."\n";
					  else
					    echo '<option selected="selected" value='.$type.'>'.$name.'</option><br/>'."\n";
					  }
					?>
			</select>
			</td>
		</tr>
			    <tr><td><B>Nom</B></td><td><input name="nom" value=""/></input></td></tr>
			    <tr><td><B>Prenom</B></td><td><input name="prenom" value=""/></input></td></tr>
		<tr>
			<td><input type="submit" name="createanedit" value="Créer le rapport" /></td>
		</tr>

	</table>

</form>
<hr />
<?php
			    if(!is_current_session_concours())
			      {
?>
<h2>Ajout d&apos;une liste de rapports</h2>
<p>N&apos;utilisez cette fonction qu&apos;en concertation avec votre ACN.</p>
<form enctype="multipart/form-data" action="index.php" method="post">
	<table>
		<tr>
			<td><input type="hidden" name="type" value="evaluations"></input> <input
				type="hidden" name="action" value="upload" /> <input type="hidden"
				name="create" value="true" /> <input type="hidden"
				name="MAX_FILE_SIZE" value="10000000" />
			</td>
		</tr>
		<tr>
			<td>Fichier csv au format correct</td>
			<td><input name="uploadedfile" type="file" />
			</td>
		</tr>
		<tr>
			<td>Choix du type de rapport</td>
			<td><select name="subtype">
					<?php
	    global $typesRapportsAll;
					$types = $typesRapportsAll;

					if(isset($_REQUEST["type"]))
					  $ttype = $_REQUEST["type"];
					else
					  $ttype = "";
					global $typesRapportsConcours;
					foreach($types as $type => $name)
					  {
					    if(isset($typesRapportsConcours[$type])) continue;
					  if($type != $ttype)
					    echo '<option value='.$type.'>'.$name.'</option><br/>'."\n";
					  else
					    echo '<option selected="selected" value='.$type.'>'.$name.'</option><br/>'."\n";
					  }
					?>
			</select>
			</td>
		</tr>
		<tr>
			<td><input type="submit" value="Importer rapports" /></td>
		</tr>

	</table>

</form>
<?php 
			      }
	}
}

function displayExport()
{
	global $typeExports;

	echo "<ul>";

	foreach($typeExports as $idexp => $exp)
	{
		$expname= $exp["name"];
		$level = $exp["permissionlevel"];
		if (getUserPermissionLevel()>=$level)
		{
			echo "<li><a href=\"export.php?action=export&amp;type=$idexp\">";
			//echo "<img class=\"icon\" width=\"40\" height=\"40\" src=\"img/$idexp-icon-50px.png\" alt=\"$expname\"/></a>";
			echo "$expname</a></li>";
		}
	}
	echo "</ul>";
}

if(false)
{
	?>


<h2>Export</h2>
<p>Ce menu permet d'exporter l'ensemble des rapports de la sélection en
	cours dans différents formats. Pour une édition des rapports
	hors-ligne, choisir le format "csv".</p>

<?php displayExport();?>
<hr />
<h2>Mise à jour d'un ou plusieurs rapports</h2>
<p>
	Le formulaire suivant vous permet d'importer un ou plusieurs rapports
	édités offline.<br /> Le fichier à importer doit avoir été récupéré au
	préalable via la fonction Export au format csv.
</p>
<?php 
displayImport();

}

if(isSecretaire())
{
	?>
<hr />


<?php 
/*
 try
{
$sql = "SELECT * FROM ".units_db." LIMIT 0,5";
$result = sql_request($sql);

$rows = array();
while ($row = mysql_fetch_object($result))
	$rows[] = $row;

$csv_reports = compileUnitsAsCSV($rows);
$filename = "csv/exemple_unites.csv";
if($handle = fopen($filename, 'w'))
{
fwrite ($handle, $csv_reports);
fclose($handle);
}
else
{
echo("Watchout: couldn't create exemple csv file ".$filename);
}
}
catch(Exception $e)
{
echo("Watchout: couldn't create exemple csv file ".$e->getMessage());
}
*/

displaySecretaryImport();

?>



<?php 
}
?>

