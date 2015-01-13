<?php 

require_once('generate_pdf.inc.php');
require_once('generate_xml.inc.php');
require_once('config.inc.php');


function type_from_node(DOMNode $node)
{
	foreach($node->childNodes as $child)
		if($child->nodeName == "type")
		return $child->nodeValue;
	return "";
}


/**
 * Zip files to an archive
 * @param filenames array(string -> string) <p>
 * Collection of pairs of loclfilename and name in the archive.
 * </p>
 * @param zipfilename string[optional] <p>
 * the name of the zip file
 * @return bool Returns zip filename on success or false on failure.
 */
function zip_files($filenames,$zipname = "reports.zip")
{
	$zip = new ZipArchive();
	if($zip->open($zipname,ZipArchive::OVERWRITE | ZipArchive::CREATE) != true)
		throw new Exception("Failed to create zip file ".$zipname);

	foreach($filenames as $localfilename => $shortfilename)
	{
		set_time_limit(0);
		if(!$zip->addFile($localfilename, $shortfilename))
		{
			echo "Failed to add file ".$shortfilename." to zip file<br/>";
			return false;
		}
	}
	$zip->close();
	return $zipname;
}

/**
 *
 * @param unknown $docs
 *
 * @return javascript to get he reports
 */
function xmls_to_pdfs2($docs)
{

	$filenames = array();
	$script = "";

	//echo "Processing ".count($docs)." docs<br/>";
	foreach($docs as $doc)
	{
		//it takes time so we tell the server the script is still alive
		set_time_limit(0);
		$nodes =$doc->getElementsByTagName("rapport");
		if($nodes)
		{
			$node = $nodes->item(0);
			$filename = replace_accents(filename_from_node($node)).".pdf";
			$local_filename = replace_accents("reports/".$filename);
			$type = type_from_node($node);

			$xsl = new DOMDocument("1.0","utf-8");
			$xsl->load(type_to_xsl($doc->type));
			$proc = new XSLTProcessor();
			$proc->importStyleSheet($xsl);
			$html = $proc->transformToXML($node);

			$pdf = HTMLToPDF($html);
			$pdf->Output($local_filename,"F");
			$filenames[$local_filename] = $filename;
		}
	}
	return $filenames;

}

function xml_to_pdfs($xml_reports)
{
	
	$filenames = array();

	$rapports = $xml_reports->firstChild->getElementsByTagName("rapport");

	//echo "Processing ".count($docs)." docs<br/>";
	foreach($rapports as $node)
	{
		//it takes time so we tell the server the script is still alive
		set_time_limit(0);
		$filename = $node->getAttribute('filename').".pdf";
		$local_filename = replace_accents("reports/".$filename);
		
		$xsl = new DOMDocument("1.0","utf-8");
		$xsl->load(type_to_xsl($node->getAttribute('type')));
		$proc = new XSLTProcessor();
		$proc->importStyleSheet($xsl);
		$html = $proc->transformToXML($node);

		$pdf = HTMLToPDF($html);
		$pdf->Output($local_filename,"F");
		$filenames[$local_filename] = $filename;
	}
	return $filenames;
}


?>
