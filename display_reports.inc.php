<?php
require_once('utils.inc.php');
require_once('manage_filters_and_sort.inc.php');
require_once('manage_sessions.inc.php');
require_once('synchro.inc.php');

function displaySummary($filters, $filter_values, $sorting_values)
{
	global $fieldsSummary;
	global $fieldsSummaryConcours;
	global $statutsRapports;
	global $filtersReports;
	global $fieldsTypes;

	global $avis_classement;

	$rows = filterSortReports($filters, $filter_values, $sorting_values);

	$rows_id = array();
	foreach($rows as $row)
		$rows_id[] = $row->id;
	$_SESSION['rows_id'] = $rows_id;
	
	$_SESSION['current_id'] = 0;

	if(is_current_session_concours())
		$fields = $fieldsSummaryConcours;
	else
		$fields = $fieldsSummary;

	if( isset($filter_values["type"]) && $filter_values["type"] == "Promotion")
	{
		$filters["avis"]["liste"] = $avis_classement;
		$filters["avis1"]["liste"] = $avis_classement;
		//	reset_tri	$filters["avis2"]["liste"] = $avis_classement;
	}

	if(isSecretaire())
	  $fields[] = "statut";

	if($filter_values['type'] != $filters['type']['default_value'] )
	{
		$new_field = array();
		foreach($fields as $field)
			if($field != 'type')
			$new_field[] = $field;
		$fields = $new_field;
	}

	displayRows($rows,$fields, $filters, $filter_values);
}


function displayFiltrage($rows, $fields, $filters, $filter_values)
{
	global $fieldsAll;
	global $actions;
	global $fieldsTypes;
	global $specialtr_fields;
	global $start_tr_fields;
	global $end_tr_fields;

	?>
			<table class="inputreport">
				<tr>
					<?php
					$count = 0;
					foreach($filters as $filter => $data)
						if(isset($data['liste']))
						{
							$count++;
							?>
					<td><?php echo $data['name'];?></td>
					<td><select
						onchange="window.location='index.php?action=view&amp;filter_<?php echo $filter?>=' + this.value;">
							<option value="<?php echo $data['default_value']; ?>">
								<?php echo $data['default_name']; ?>
							</option>
							<?php
							foreach ($data['liste'] as $value => $nomitem)
							{
								if(is_numeric($value))
									$value = strval($value);
								$cur_val = $filter_values[$filter];
								if(is_numeric($cur_val))
									$cur_val = strval($cur_val);
								$sel = "";
								if ($value === $cur_val)
									$sel = " selected=\"selected\"";
								echo "<option value=\"".$value."\" $sel>".$nomitem."</option>\n";
							}
							?>
					</select></td>
					<?php 
					if($count %3 == 0)
						echo '</tr><tr>';
						}
						?>
					<td></td>
					<td style="width: 10em;">
							<a href="index.php?action=view&amp;reset_filter=">Réinitialiser
								filtres</a>
						
					</td>

				</tr>
			</table>
<?php
}

function showIconAvis($fieldID,$data)
{
	global $icones_avis;
	if ((substr( $fieldID,0,4)==="avis") and isset($icones_avis[$data]))
	{
		$url = $icones_avis[$data];
		echo "<img class=\"iconeAvis\" src=\"".$url."\">&nbsp;";
	}
}

function displayStatsConcours()
{
	$stats = get_bureau_stats();
	$roles = array("rapporteur","rapporteur2","rapporteur3");
	$rapporteurs = listNomRapporteurs();
	?>
<center>
	<table>
		<tr>
			<?php
			foreach($stats as $niveau => $data)
				echo "<th>Nombre de candidats ".$niveau."</th>";
			?>
		</tr>
		<tr valign="top">
			<?php
			foreach($stats as $niveau => $data)
			{
				?>
			<td>
				<table class="stats">
					<tr>
						<th>login</th>
						<th>rapp</th>
						<th>rapp 2</th>
						<th>rapp 3</th>
						<th>Total</th>
					</tr>
					<?php
					foreach($data as $login => $data_rapporteur)
					{
						$nom= isset($rapporteurs[$login])? $rapporteurs[$login] : $login;
						echo "<tr ><td>".$nom."</td>";
						$total = isset($data_rapporteur["total"]) ? $data_rapporteur["total"] : 0;
						foreach($roles as $role)
						{
							if(isset($data_rapporteur[$role]))
							{
								$stat = $data_rapporteur[$role];
								echo "<td>".$stat."</td>";
							}
							else
								echo "<td></td>";
						}
						echo "<td>".$total."</td>";
						echo "</tr>";
					}
					?>
				</table>
			</td>
			<?php
			}
			?>
		</tr>
	</table>
</center>
<?php
}

function displayStatsSession()
{
	$stats = get_bureau_stats();
	$rapporteurs = listNomRapporteurs();
	$roles = array("rapporteur","rapporteur2","rapporteur3");
	?>
<center>
	<table class="stats">
		<tr>
			<th>Rapporteur</th>
			<th>total</th>
			<th>1</th>
			<th>2</th>
			<th>3</th>
		</tr>
		<?php
		foreach($stats as $rapporteur => $compteurs)
		{
			$nom= isset($rapporteurs[$rapporteur])? $rapporteurs[$rapporteur] : $rapporteur;
			echo "<tr><td>".$nom."</td>";
			echo "<td>".$compteurs["total"]."</td>";
			echo "<td>".$compteurs["rapporteur"]."</td>";
			echo "<td>".$compteurs["rapporteur2"]."</td>";
			echo "<td>".$compteurs["rapporteur3"]."</td>";
			echo "</tr>\n";
		}
		?>
	</table>
</center>
<?php 
}

function displayStats()
{
	if(is_current_session_concours())
		displayStatsConcours();
	else
		displayStatsSession();
}

function displayRowCell($row, $fieldID)
{
	global $fieldsAll;
	    global $typesRapportsAll;
	$bur = isBureauUser();
	$sec = isSecretaire() || ( $bur && isSecretaire(getLogin() , false));
	if(isACN() && is_current_session_concours())
	  $sec=false;

	$concours = getConcours();	
	$rapporteurs = 	listUsers();
	//	$rapporteurs = listNomRapporteurs();
	
	$login = getLogin();
	$is_rapp1 = isset($row->rapporteur) && ($login == $row->rapporteur);
	$is_rapp2 = isset($row->rapporteur2) && ($login == $row->rapporteur2);
	$is_rapp3 = isset($row->rapporteur3) && ($login == $row->rapporteur3);
	$is_rapp = $is_rapp1 || $is_rapp2 ||$is_rapp3;

	$title = $fieldsAll[$fieldID];
	echo '<td>';
	$data = $row->$fieldID;

	global $fieldsTypes;
	$type = isset($fieldsTypes[$fieldID]) ?  $fieldsTypes[$fieldID] : "";

	global $statutsRapports;

	if($type=="rapporteur")
	{
	  if(is_field_editable($row, $fieldID))
		{
			?>
<form action="/">
	<select class="sproperty" name="value">
		<?php
		echo "<option value=\"\"></option>\n";

		  $concours_ouverts = getConcours();
		foreach($rapporteurs as $rapporteur => $data)
		{
		  
		  		  if(isset($row->concours) 
		     && $row->concours != "" 
		     && isset($concours_ouverts[$row->concours])		     
		     && !in_array($rapporteur,$concours_ouverts[$row->concours]->jures))
		    continue;
		  
		  if(is_rapporteur_allowed($data,$row))
		    {
			$selected = ($rapporteur == $row->$fieldID) ? "selected=on" : "";
			echo "<option ".$selected." value=\"".$rapporteur."\">".$data->description."</option>\n";
		    }
		}
		?>
	</select>
	<input type="hidden" name="action" value="set_property" />
	    <input type="hidden" name="property" value=<?php echo '"'.$fieldID.'"'; ?> />
	    <input type="hidden" name="id_origine" value=<?php echo '"'.$row->id_origine.'"'; ?> />
</form>
	<?php
		}
		else
			echo (isset($rapporteurs[$row->$fieldID]) ? $rapporteurs[$row->$fieldID]->description : $row->$fieldID);
	}
	else if($type=="avis")
	{
		global $typesRapportToAvis;
		global $tous_avis;

		$listeavis = isset($typesRapportToAvis[$row->type]) ? $typesRapportToAvis[$row->type] : array();
		if(isset($filters['avis']) && isset($data['avis']['liste']))
			$avis = $data['avis']['liste'];
		
		if(is_field_editable($row, $fieldID))
		{
			?>
<form>
		  <select class="sproperty" name="value">
		<?php
		foreach($listeavis as $key => $value)
		{
			$selected = (strval($key) === $row->$fieldID) ? "selected=on" : "";
			echo "<option ".$selected." value=\"".$key."\">".$value."</option>\n";
		}
		?>
	</select>
	<input type="hidden" name="action" value="set_property" />
	    <input type="hidden" name="property" value=<?php echo "\"".$fieldID."\""; ?> />
	    <input type="hidden" name="id_origine" value=<?php echo '"'.$row->id_origine.'"'; ?> />
</form>
	<?php
		}
		else if($fieldID == "avis" || $sec || 
			( !get_option("double_aveugle_strict") && !get_option("show_avis_double_aveugle") &&  (!$is_rapp || !isset($row->statut) || $row->statut != "doubleaveugle"))
			)
		{
			showIconAvis($fieldID,$data);
			//echo get_config("double_aveugle_strict");
			echo (isset($tous_avis[$data]) && !is_array($tous_avis[$data]) )? $tous_avis[$data] : $data;
		}
	}
	else if($fieldID == "concours")
	{
		echo isset($concours[$row->$fieldID]) ? $concours[$row->$fieldID]->intitule : $row->$fieldID;
	}
	else if($fieldID=="sousjury")
	{
		echo $row->$fieldID;
	}
	else if($fieldID=="nom")
	{
		echo "<a href=\"?action=edit&amp;id=".($row->id)."\">";
		echo '<span class="valeur">'.$data.'</span>';
		echo '</a>';
	}
	else if( $type == "unit")
	{
		$prettyunits = unitsList();
		$data = isset($prettyunits[$row->$fieldID]) ? ($prettyunits[$row->$fieldID]->nickname." (".$row->$fieldID.")") : $row->$fieldID;
		echo '<span class="valeur">'.$data.'</span>';
	}
	else if($type == "statut")
	  {

	    echo isset($statutsRapports[$data]) ? $statutsRapports[$data]: $data;
	  }
	else if($fieldID == "type" && isset($typesRapportsAll[$data]))
	  {
	    $label = $typesRapportsAll[$data];
	    $num = 25;
	    if(strlen($label) > $num)
	      {
		$arr = explode(" ",$label);
		$tot = 0;
		$lab = "";
		foreach($arr as $piece)
		  {
		  $tot += strlen($piece);
		  $lab .= $piece." ";
		  if($tot > $num) 
		    {
		    $lab .= "<br/>"; 
		    $tot = 0;
		    }
		  }
		$label = $lab;
	      }
	    echo '<span class="valeur">'.$label.'</span>';
	  }
	else
		echo '<span class="valeur">'.$data.'</span>';
		
	echo "</td>\n";
}

function display_updates()
{
	if(isSecretaire() && !isset($_SESSION["update_performed"]))
	{
	  synchronizeWithDsiMembers($currentSection());
		$_SESSION["update_performed"] = true;
	}
}


function displayStatutMenu()
{
	?>
</tr>
<tr><td>
				<form
					onsubmit="return confirm('Changer les statuts des rapports?');"
					method="post" action="index.php">
					<table>
						<tr>
							<td><input type="submit" value="Changer statuts" />
							</td>
							<td><select name="new_statut">
									<?php
									global $statutsRapports;
									global $statutsRapportsACN;
									global $statutsRapportsMulti;
									//	  display_select($row, $fieldID,$statutsRapportsIndiv,$readonly);
									$statuts = isACN() ? $statutsRapportsACN : $statutsRapportsMulti;									

									foreach ($statuts as $val => $nom)
									{
									  if($val == "audition" && !is_current_session_concours())
									    continue;
									  $sel = "";
										echo "<option value=\"".$val."\" $sel>".$nom."</option>\n";
									}
									?>
							</select> <input type="hidden" name="action"
								value="change_statut" />
							</td>
						</tr>
					</table>
				</form>
							    <?php if(!is_current_session_concours())
							    {
?>
				<form onsubmit="return confirm('Supprimer ces rapports?');"
					method="post" action="index.php">
					<input type="hidden" name="action" value="deleteCurrentSelection" />
					<input type="submit" value="Supprimer rapports" />
				</form>
		<?php
    }
		if(is_current_session_concours())
		{
		?> 
				<form method="post" action="index.php"
					onsubmit="return confirm('Affecter les sections de jury?');">
					<input type="hidden" name="action" value="affectersousjurys2" /> <input
						type="submit" value="Affecter sections de jurys" /> <input type="hidden"
						name="admin_concours"></input>
				</form>
		<?php 
		}
		?>
		
</td>
<?php 
}

function displayActionsMenu($row, $excludedaction = "", $actions)
{
	$id = $row->id;
	$id_origine = $row->id_origine;
	echo "<table><tr>";
	foreach($actions as $action => $actiondata)
	{
		if ($action!=$excludedaction)
		{
			$title = $actiondata['title'];
			$icon = $actiondata['icon'];
			$page = $actiondata['page'];
			$level = $actiondata['level'];
			if(getUserPermissionLevel() >= $level )
			{
			  if(isset($actiondata['warning']))
			    {
			      echo "<td>\n<a ";
			      echo " href=\"$page?action=$action&amp;id=$id&amp;id_origine=$id_origine\"";
			      echo " onclick=\"return confirm('".$actiondata['warning']."')\" ";
			      echo ">\n";
			    }
			  else
			    {
				echo "<td>\n<a href=\"$page?action=$action&amp;id=$id&amp;id_origine=$id_origine\">\n";
			    }
				echo "<img class=\"icon\" width=\"24\" height=\"24\" src=\"$icon\" alt=\"$title\"/>\n</a>\n</td>\n";
			}
		}
	}
	echo "</tr></table>";
}



function displayRows($rows, $fields, $filters, $filter_values)
{
	global $fieldsAll;
?>
<table>
	<tr>
		<td>
		<?php displayFiltrage($rows, $fields, $filters, $filter_values); ?>
		</td>
   <?php if(isSecretaire()) displayStatutMenu(); ?>
	</tr>
</table>
<hr />
<p>
   <?php  echo count($rows).(is_current_session_concours() ? " candidatures" : " demandes d'évaluation");?>
</p>

<?php 
$bur = isBureauUser();
if($bur)
	displayStats();
?>
<table class="summary">
	<tr>
		<th class="oddrow"><span class="nomColonne"></span></th>
		<?php

		foreach($fields as $fieldID)
			if(isset($fieldsAll[$fieldID]))
			{
				$title = $fieldsAll[$fieldID];
				$style = getStyle("",true);
				?>
		<th class="<?php echo $style;?>"><span class="nomColonne"> <?php 
		echo '<a href="?action=view&amp;reset_tri='.$fieldID."\">".$title.'</a>';
		?>
		</span>
		</th>
		<?php
			}
			?>
	</tr>

	<?php 
	global $actions1;
	global $actions2;

	$odd = false;
	foreach($rows as $row)
	{
		$conflit = is_in_conflict_efficient($row, getLogin());
		$style = getStyle("",$odd,$conflit);
		$odd = !$odd;
	?>
	<tr id="t<?php echo $row->id;?>" class="<?php echo $style;?>">
		<td>
<?php
	   	   echo "<a href=\"?action=edit&amp;id=".$row->id."\"><img class=\"icon\" width=\"24px\" height=\"24px\" src=\"img/details-icon-24px.png\"></img></a>";
?>
	   <span class="actions1"></span>
</td>
<?php
		foreach($fields as $fieldID)
		  displayRowCell($row, $fieldID);
?>
		<td>
		   <?php if(!is_current_session_concours()) displayActionsMenu($row,"", $actions2); ?>
		</td>
	</tr>
	<?php 
	}
	?>
	</table>
<script type="text/javascript">
	    <?php 
	foreach(array("actions1","actions2") as $label)
	  {
	    global $$label;
	foreach($$label as $action => $actiondata)
	{
	  $level = $actiondata['level'];
	  if(getUserPermissionLevel() >= $level )
	    {
	  $title = $actiondata['title'];
	  $icon = $actiondata['icon'];
	  $page = $actiondata['page'];
	  echo "$('.".$label."').append('";
	  echo "<input type=\"image\" class=\"link".$action."\" ";
	  echo "src=\"$icon\" width=\"24\" height=\"24\">";
	  echo "</input>";
	  echo "');\n\n";
	  echo "$('.link".$action."').click( function () {\n";
	  $location = $page."?action=".$action;
	  echo "var id = this.closest('tr').id.substring(1);\n";
	  echo "var location = '".$location."'+'&id='+id;\n";
	  if(isset($actiondata['warning']))
	    {
	      echo "var answer = confirm('".$actiondata['warning']."');";
	      echo "if (answer) {";
	      echo "window.location = location;\n";
	      echo "};";
	    }
	  else
	    {
	      echo "window.location = location;\n";
	    }
	    echo "});\n\n";
	    }
	}
	  }
	?>
</script>



	    <?php
	    }







