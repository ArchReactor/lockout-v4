<?php
//header('X-Accel-Buffering: no');


session_write_close();

echo "Update starting<br />\n";

function pressButton($nodeIp) {
    $url = "http://{$nodeIp}/button/Fetch/press";

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, 1);
    //curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_setopt($ch, CURLOPT_USERPWD, $_ENV['ESPHOME_USERPASS']);
    curl_setopt($ch, CURLOPT_POSTFIELDS, "");

    // Set a timeout to prevent hanging
    curl_setopt($ch, CURLOPT_TIMEOUT, 15); 

    curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    // Check for cURL errors
    if (curl_errno($ch)) {
        throw new Exception(curl_error($ch));
    }

    // Check for HTTP errors (e.g., 404, 500)
    if ($httpCode !== 200) {
        throw new Exception("$nodeIp HTTP Error: " . $httpCode . " - " . $response);
    }
    
    curl_close($ch);
}

$handle = fopen('lockouts.csv','r');
while ( ($data = fgetcsv($handle) ) !== FALSE ) {
    if(count($data) < 2) {
        echo "Skipping line with fewer than 2 columns: " . implode(',', $data) . "<br />\n";
        continue;
    }
    try {
        echo "Fetching {$data[0]} ...";
        pressButton($data[1]);
        echo "done. <br />\n";
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "<br />\n";
    }
}
ini_set('auto_detect_line_endings',FALSE);



echo "Update complete<br />\n";

?>

<p>
<a href="<?php echo $_ENV['UPDATE_RETURN_URL']; ?>">Return</a>
