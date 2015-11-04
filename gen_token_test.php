<?php

$pubkeyStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq9s407QkMiZkXF0juCGj ti6iWUDzqEmP+Urs3+g2zOf+rbIAZVZItS5a4BZlv3Dux3Xnmhrz240OZMBO1cNc poEQNij1duZlpJY8BJiptlrj3C+K/PSp0ijllnckwvYYpApm3RxC8ITvpmY3IZTr RKloC/XoRe39p68ARtxXKKW5I/YYxFucY91b6AEOUNaqMFEdLzpO/Dgccaxoc+N1 SMfZOKue7aH0ZQIksLN7OQGVoiuf9wR2iSz3+FA+mMzRIP+lDxI4JE42Vvn1sYmM CY1GkkWUSzdQsfgnAIvnbepM2E4/95yMdRPP/k2Qdq9ja/mwEMTfA0yPUZ7Liywo ZwIDAQAB";

$azStackUserID = $_GET["azStackUserID"];
$nonce = $_GET["nonce"];

if (!$azStackUserID || !$nonce) {
	$res['r'] = -1;
	echo json_encode($res);
	return;
}

//check username / password in your backend
//...coding here...
//(You can check in database)

/*
  //if username/pass is incorrect:
  if(incorrect username/pass){
	$res['r'] = -1;
	echo json_encode($res);
	return;
  }
 */

//username / password is correct, return identity token

$dataobject['azStackUserID'] = $azStackUserID;
$dataobject['nonce'] = $nonce;
$data = json_encode($dataobject);

$key = "-----BEGIN PUBLIC KEY-----\n" . chunk_split($pubkeyStr, 64, "\n") . '-----END PUBLIC KEY-----';

$key = openssl_get_publickey($key);

$pubkey = openssl_pkey_get_public($key);

if (openssl_public_encrypt($data, $encrypted, $pubkey)) {
	$encrypted = base64_encode($encrypted);

	$res['r'] = 1;//sucess
	$res['token'] = $encrypted;
	echo json_encode($res);
} else {
	$res['r'] = -2;//error
	echo json_encode($res);
}	
