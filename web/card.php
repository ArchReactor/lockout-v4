<?php

$url = "http://{$_ENV['CARDSCANNER_HOST']}/text_sensor/Last%20Tag";

$data = json_decode(file_get_contents($url));
print($data->state);
