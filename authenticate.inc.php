<?php 
require_once("config_tools.inc.php");
$is_maintenance = (get_config("maintenance","off",false,"0") === "on");

			?>

<div class="large">
	<div class="header">
		<h2><span>Comité National de la Recherche Scientifique</span></h2>
		<br/>
		<br/>
		<br/>
		<br/>

<br/>
  <br/>
  <h3>"Marmotte", une interface de gestion des rapports pour les sections du Comit&eacute; National.</h3>
  <br/>
  <br/>
<br/>

<p>
<font color="red">
	     [12/06/2015 08:00]Site ferme jusqu'a 9h pour maintenance
</font>
</p>

<?php 
if($is_maintenance)
{
?>
<p><font color="red">
Site fermé pour maintenance, accès temporairement réservé aux administrateurs.
</font>
</p>
<?php 
}
?>
</h3>
		</div>

	<div class="content"> 
	 <?php 
	 if(isset($_REQUEST["action"]) && ($_REQUEST["action"] == "auth_marmotte"))
	 {
	 ?>
	<h3>Authentification Marmotte</h3>
	<form method="POST">
	<table>
		<tr>
			<td><span class="label">Login</span></td>
			<td><input name="login" type="text" value=""></input></td>
			<td rowspan="2"><input type="submit" value="Valider">
			<input type="hidden" name="action" value="auth_marmotte"></td>
		</tr>
		<tr>
			<td><span class="label">Mot de passe</span></td>
			<td><input name="password" type="password" value=""></input></td>
		</tr>
	</table>
	 <?php 
	 }
	 else
	 {
	 ?>
<p>
<font color="red">
	     [12/06/2015 08:00]Site ferme jusqu'a 9h pour maintenance
</font>
</p>

<!--
<p><font color="red">
[10/06/2015 09:19] L'authentification par login e-valuation est temporairement indisponible
suite &agrave; un probl&egrave;me sur un serveur de la DSI.
En cas de besoin urgent, merci de contacter votre secr&eacute;taire scientifique afin d'obtenir un mot de passe provisoire.
</font>
</p>
-->
<!--

	     <h2><a href="index.php?action=auth_janus">Authentification Janus (personnels des unit&eacute;s CNRS)</a></h2>
<br/>
	     <h2><a href="index.php?action=auth_marmotte">Authentification Marmotte (personnels hors-unit&eacute;s CNRS, demandez un mot de passe &agrave; votre ACN)</a></h2>
	 <?php 
	 }
	 ?>
	<br/>
	<br/>
-->
 <br/>
  <br/>
<br/>	
  <br/>
<br/>	
  <br/>
  <table>
  <tr>
  <td width="60%"></td>
  <td width="40%">
  <h3>Contributeurs Marmotte 2.0</h3>
  <ul>
  <li>Hugo Gimbert (d&eacute;veloppeur, coordinateur technique, section 6)</li>
  <li>Yann Ponty (d&eacute;veloppeur, section 6)</li>
  <li>Mathias Velazquez (beta-testeur, coordinateur d&eacute;ploiement SSC, section 15)</li>
  <li>Caroline Strube (beta-testeuse, formatrice, section 25)</li>
  <li>Sophie Achard (beta-testeuse, formatrice, section 7)</li>
  <li>Laurent Chazaly (beta-testeur, formateur, SGCN)</li>
  <li>Guillaume Lapeyre (beta-testeur, formateur, section 19)</li>
<li>Mich&egrave;le Desumeur (beta-testeuse ACN, SGCN)</li>
 </ul>
 </td>
 </tr>
 </table>
 </div>
  </div>
 </div>
<!-- <iframe width="90%" height="20%" src="https://lejournal.cnrs.fr/"></iframe>  -->
