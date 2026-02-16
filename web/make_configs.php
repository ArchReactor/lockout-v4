<?php

if (PHP_SAPI !== 'cli') {
    die("This script must be run from the command line.");
} 

$handle = fopen('lockouts.csv','r');
while ( ($data = fgetcsv($handle) ) !== FALSE ) {
    if(count($data) < 4) {
        echo "Skipping line with fewer than 4 columns: " . implode(',', $data) . "\n";
        continue;
    }
    echo "Creating config for {$data[0]} ... \n";
    if(file_exists("/config/{$data[0]}.yaml")) {
        echo " ..Backing up /config/{$data[0]}.yaml to /config/{$data[0]}.yaml.bak\n";
        if(file_exists("/config/{$data[0]}.yaml.bak")) {
            unlink("/config/{$data[0]}.yaml.bak");
        }
        rename("/config/{$data[0]}.yaml", "/config/{$data[0]}.yaml.bak");
    }
    $file = "packages:
  - !include
    file: templates/lockout.yaml
    vars:
      name: {$data[0]}
      ip: {$data[1]}
      groups: \"{$data[2]}\"
      activeTime: \"{$data[3]}\"
      webhost: {$_ENV['LOCKOUT_WEBHOST']}
      webuser: {$_ENV['ESPHOME_USER']}
      webpass: {$_ENV['ESPHOME_PASSWORD']}
";
    echo " ..Writing /config/{$data[0]}.yaml\n";
    file_put_contents("/config/{$data[0]}.yaml", $file);
}
ini_set('auto_detect_line_endings',FALSE);
echo "Done.\n";
