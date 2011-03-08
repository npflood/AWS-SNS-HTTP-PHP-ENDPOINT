<?

//////
//// CONFIGURATION
//////

//For Debugging.
$logToFile = true;

//Should you need to check that your messages are coming from the correct topicArn
$restrictByTopic = true;
$allowedTopic = "arn:aws:sns:us-east-1:318514470594:WAYJ_NowPlaying_Test";

//For security you can (should) validate the certificate, this does add an additional time demand on the system.
//NOTE: This also checks the origin of the certificate to ensure messages are signed by the AWS SNS SERVICE.
//Since the allowed topicArn is part of the validation data, this ensures that your request originated from
//the service, not somewhere else, and is from the topic you think it is, not something spoofed.
$verifyCertificate = true;
$sourceDomain = "sns.us-east-1.amazonaws.com";
 

//////
//// OPERATION
//////

$signatureValid = false;
$safeToProcess = true; //Are Security Criteria Set Above Met? Changed programmatically to false on any security failure.

if($logToFile){
	////LOG TO FILE:
	$dateString = date("Ymdhis");
	$dateString = $dateString."_r.txt";

	$myFile = $dateString;
	$fh = fopen($myFile, 'w') or die("Log File Cannot Be Opened.");
}


//Get the raw post data from the request. This is the best-practice method as it does not rely on special php.ini directives
//like $HTTP_RAW_POST_DATA. Amazon SNS sends a JSON object as part of the raw post body.
$json = json_decode(file_get_contents("php://input"));


//Check for Restrict By Topic
if($restrictByTopic){
	if($allowedTopic != $json->TopicArn){
		$safeToProcess = false;
		if($logToFile){
			fwrite($fh, "ERROR: Allowed Topic ARN: ".$allowedTopic." DOES NOT MATCH Calling Topic ARN: ". $json->TopicArn . "\n");
		}
	}
}


//Check for Verify Certificate
if($verifyCertificate){

	//Check For Certificate Source
	$domain = getDomainFromUrl($json->SigningCertURL);
	if($domain != $sourceDomain){
		$safeToProcess = false;
		if($logToFile){
			fwrite($fh, "Key domain: " . $domain . " is not equal to allowed source domain:" .$sourceDomain. "\n");
		}
	}
	
	
	
	//Build Up The String That Was Originally Encoded With The AWS Key So You Can Validate It Against Its Signature.

	$validationString = "";
	$validationString .= "Message\n";
	$validationString .= $json->Message . "\n";
	$validationString .= "MessageId\n";
	$validationString .= $json->MessageId . "\n";
	if($json->Subject != ""){
		$validationString .= "Subject\n";
		$validationString .= $json->Subject . "\n";
	}
	$validationString .= "Timestamp\n";
	$validationString .= $json->Timestamp . "\n";
	$validationString .= "TopicArn\n";
	$validationString .= $json->TopicArn . "\n";
	$validationString .= "Type\n";
	$validationString .= $json->Type . "\n";
	
	if($logToFile){
		fwrite($fh, "Data Validation String:");
		fwrite($fh, $validationString);
	}
	
	$signatureValid = validateCertificate($json->SigningCertURL, $json->Signature, $validationString);
	
	if(!$signatureValid){
		$safeToProcess = false;
		if($logToFile){
			fwrite($fh, "Data and Signature Do No Match Certificate or Certificate Error.\n");
		}
	}else{
		if($logToFile){
			fwrite($fh, "Data Validated Against Certificate.\n");
		}
	}
}


//TODO: Add Safe To Process Checks To Each Of The Below



if($safeToProcess){

	//Handle A Subscription Request Programmatically
	if($json->Type = "SubscriptionConfirmation"){
		//RESPOND TO SUBSCRIPTION NOTIFICATION BY CALLING THE URL
		
		if($logToFile){
			fwrite($fh, $json->SubscribeURL);
		}
		
		$curl_handle=curl_init();
		curl_setopt($curl_handle,CURLOPT_URL,$json->SubscribeURL);
		curl_setopt($curl_handle,CURLOPT_CONNECTTIMEOUT,2);
		curl_exec($curl_handle);
		curl_close($curl_handle);	
	}
	
	
	//Handle a Notification Programmatically
	if($json->Type = "Notification"){
		//Do what you want with the data here.
		//fwrite($fh, $json->Subject);
		//fwrite($fh, $json->Message);
	}
}

//Clean Up For Debugging.
if($logToFile){
	ob_start();
	print_r( $json );
	$output = ob_get_clean();

	fwrite($fh, $output);

	////WRITE LOG
	fclose($fh);
}


//A Function that takes the key file, signature, and signed data and tells us if it all matches.
function validateCertificate($keyFileURL, $signatureString, $data){
	
	$signature = base64_decode($signatureString);
	
	
	// fetch certificate from file and ready it
	$fp = fopen($keyFileURL, "r");
	$cert = fread($fp, 8192);
	fclose($fp);
	
	$pubkeyid = openssl_get_publickey($cert);
	
	$ok = openssl_verify($data, $signature, $pubkeyid, OPENSSL_ALGO_SHA1);
	
	
	if ($ok == 1) {
	    return true;
	} elseif ($ok == 0) {
	    return false;
	    
	} else {
	    return false;
	}	
}

//A Function that takes a URL String and returns the domain portion only
function getDomainFromUrl($urlString){
	$domain = "";
	$urlArray = parse_url($urlString);
	
	if($urlArray == false){
		$domain = "ERROR";
	}else{
		$domain = $urlArray['host'];
	}
	
	return $domain;
}




echo "Private Function.";

?>