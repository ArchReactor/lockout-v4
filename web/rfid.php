<?php

//inputs:
//id
//name

date_default_timezone_set($_ENV['TZ']);

$url = $_ENV['CIVICRM_WEBSITE'].$_ENV['CIVICRM_APIv4URI'].'/Activity/create';
$params = [
  'values' => ['source_contact_id' => $_REQUEST['id'], 'activity_type_id' => $_ENV['CIVICRM_RFID_ACTVITY'], 'status_id' => 2, 'subject' => $_REQUEST['name'], 'activity_date_time' => date('Y-m-d H:i:s'), 'assignee_contact_id' => [$_REQUEST['id']]],
];
$request = stream_context_create([
  'http' => [
    'method' => 'POST',
    'header' => [
      'Content-Type: application/x-www-form-urlencoded',
      'X-Civi-Auth: Bearer '.$_ENV['CIVICRM_AUTH'],
      'X-Civi-Key: '.$_ENV['CIVICRM_KEY']
    ],
    'content' => http_build_query(['params' => json_encode($params)]),
  ]
]);

echo file_get_contents($url, FALSE, $request);
